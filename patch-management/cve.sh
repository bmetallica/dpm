#!/bin/bash

# ======================================================================
# MASTER-SKRIPT: Download, Filterung & PostgreSQL-Import der Debian-CVEs
# Quelle: Debian Security Tracker (JSON)
# ======================================================================

# --- KONFIGURATION ---
URL="https://security-tracker.debian.org/tracker/data/json"
WORK_DIR=$(mktemp -d /tmp/dpm_cve.XXXXXX)
RAW_FILE="$WORK_DIR/cve_raw.json"
TSV_FILE="$WORK_DIR/cve_filtered.tsv"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LOG_FILE="$SCRIPT_DIR/cve.log"
LOCK_FILE="/tmp/dpm_cve.lock"

# PostgreSQL-Details
PG_USER="USERNAME"
PG_PASSWORD="PASSWORD"
PG_HOST="HOSTNAME"
PG_DB="DBNAME"
PG_PORT="${PG_PORT:-5432}"

MIN_SIZE_BYTES=50000000      # Rohdaten sind ca. 100 MB groß
MIN_RECORDS=10000            # Sicherheitsgrenze: weniger Datensätze => Import abbrechen
MAX_DOWNLOAD_TRIES=5

# Ausgabe zusätzlich in Logdatei schreiben (Cron leitet stdout nach /dev/null)
exec > >(tee -a "$LOG_FILE") 2>&1

# cleanup-Funktion
cleanup() {
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

# Nur eine Instanz gleichzeitig
exec 9>"$LOCK_FILE"
if ! flock -n 9; then
    echo "$(date '+%F %T') ⚠ cve.sh läuft bereits - Abbruch."
    exit 1
fi

run_psql() {
    PGPASSWORD="$PG_PASSWORD" PGOPTIONS="-c client_min_messages=warning" psql -X -q -v ON_ERROR_STOP=1 -h "$PG_HOST" -p "$PG_PORT" -U "$PG_USER" -d "$PG_DB" "$@"
}

echo "======================================================================"
echo "🚀 $(date '+%F %T') STARTE DEBIAN CVE-UPDATE"
echo "======================================================================"

# --- 1. DOWNLOAD (immer frisch) ---
echo "--- 1. Download der Rohdaten ---"
for try in $(seq 1 $MAX_DOWNLOAD_TRIES); do
    rm -f "$RAW_FILE"
    if curl -sS --fail --compressed --max-time 600 "$URL" -o "$RAW_FILE"; then
        FILE_SIZE=$(stat -c%s "$RAW_FILE" 2>/dev/null || echo 0)
        if [ "$FILE_SIZE" -ge "$MIN_SIZE_BYTES" ] && jq -e 'type == "object"' "$RAW_FILE" > /dev/null 2>&1; then
            echo "✅ Download erfolgreich. Größe: $(numfmt --to=iec --suffix=B $FILE_SIZE)"
            break
        fi
        echo "⚠ Datei zu klein oder kein gültiges JSON ($FILE_SIZE Bytes)."
    else
        echo "❌ Download fehlgeschlagen."
    fi
    if [ "$try" -eq "$MAX_DOWNLOAD_TRIES" ]; then
        echo "❌ FATALER FEHLER: Download nach $MAX_DOWNLOAD_TRIES Versuchen aufgegeben."
        exit 1
    fi
    echo "   Neuer Versuch in 60s ($try/$MAX_DOWNLOAD_TRIES)..."
    sleep 60
done

# --- 2. POSTGRESQL SCHEMA-ANPASSUNG ---
echo "--- 2. PostgreSQL Schema-Anpassung ---"
if run_psql <<'EOSQL'
CREATE TABLE IF NOT EXISTS debian_cve (
    cve_id VARCHAR(50) NOT NULL,
    package_name VARCHAR(100) NOT NULL,
    distro_name VARCHAR(50) NOT NULL,
    fixed_version VARCHAR(100),
    repository_version VARCHAR(100),
    current_status VARCHAR(50) NOT NULL,
    priority_level VARCHAR(50),
    priority_color VARCHAR(10),
    description TEXT,
    last_modified TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT debian_cve_pkey PRIMARY KEY (cve_id, package_name, distro_name)
);
ALTER TABLE debian_cve ADD COLUMN IF NOT EXISTS distro_name VARCHAR(50);
ALTER TABLE debian_cve ADD COLUMN IF NOT EXISTS fixed_version VARCHAR(100);
ALTER TABLE debian_cve ADD COLUMN IF NOT EXISTS repository_version VARCHAR(100);
ALTER TABLE debian_cve ADD COLUMN IF NOT EXISTS priority_color VARCHAR(10);
ALTER TABLE debian_cve ALTER COLUMN fixed_version TYPE VARCHAR(255);
ALTER TABLE debian_cve ALTER COLUMN repository_version TYPE VARCHAR(255);
CREATE INDEX IF NOT EXISTS idx_debian_cve_pkg_distro ON debian_cve (package_name, distro_name);

CREATE TABLE IF NOT EXISTS cve_meta (
    id INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    last_update TIMESTAMPTZ,
    record_count INTEGER,
    distros TEXT[]
);
EOSQL
then
    echo "✅ Schema aktuell."
else
    echo "❌ FEHLER: Schema-Anpassung fehlgeschlagen."
    exit 1
fi

# --- 3. JSON-VERARBEITUNG ---
# Übernommen werden alle Einträge, die ein Paket tatsächlich betreffen:
#   - status "open" (noch kein Fix)
#   - status "resolved" mit echter fixed_version ("0" = nie betroffen)
# Verworfen werden urgency "unimportant" und status "undetermined".
# @tsv maskiert Tab/Zeilenumbruch/Backslash passend für COPY.
echo "--- 3. JSON-Verarbeitung ---"
if ! jq -r '
    to_entries[] | select(.value | type == "object") |
    .key as $pkg |
    .value | to_entries[] |
    .key as $cve | .value as $data |
    ($data.releases // {}) | to_entries[] |
    .key as $distro | .value as $rel |
    ($rel.urgency // "not yet assigned") as $urgency |
    select($urgency != "unimportant") |
    select($rel.status == "open"
           or ($rel.status == "resolved" and ($rel.fixed_version // "0") != "0")) |
    [$cve, $pkg, $distro,
     ($rel.fixed_version // ""),
     ($rel.repositories[$distro] // ""),
     $rel.status, $urgency,
     ($data.description // "")] | @tsv
' "$RAW_FILE" > "$TSV_FILE"; then
    echo "❌ FATALER FEHLER: jq-Verarbeitung fehlgeschlagen."
    exit 1
fi

RECORD_COUNT=$(wc -l < "$TSV_FILE")
echo "✅ $RECORD_COUNT relevante Datensätze extrahiert."
if [ "$RECORD_COUNT" -lt "$MIN_RECORDS" ]; then
    echo "❌ FATALER FEHLER: Unplausibel wenige Datensätze - Import abgebrochen."
    exit 1
fi

# --- 4. DATEN-IMPORT ---
# Staging-Tabelle per COPY befüllen, dann Upsert und veraltete Einträge löschen.
# Einträge von Distributionen, die nicht mehr im Feed sind (z.B. bullseye),
# bleiben als letzter bekannter Stand erhalten.
echo "--- 4. Import in PostgreSQL ---"
if run_psql <<EOSQL
BEGIN;
CREATE TEMP TABLE cve_staging (
    cve_id TEXT, package_name TEXT, distro_name TEXT,
    fixed_version TEXT, repository_version TEXT,
    current_status TEXT, priority_level TEXT, description TEXT
) ON COMMIT DROP;

\copy cve_staging FROM '$TSV_FILE'

INSERT INTO debian_cve (cve_id, package_name, distro_name, fixed_version, repository_version,
                        current_status, priority_level, priority_color, description, last_modified)
SELECT DISTINCT ON (cve_id, package_name, distro_name)
       cve_id, package_name, distro_name,
       NULLIF(fixed_version, ''), NULLIF(repository_version, ''),
       current_status, priority_level,
       CASE priority_level
           WHEN 'high' THEN 'RED'
           WHEN 'medium' THEN 'ORANGE'
           WHEN 'low' THEN 'YELLOW'
           WHEN 'end-of-life' THEN 'GRAY'
           ELSE 'BLUE'
       END,
       description, NOW()
FROM cve_staging
ON CONFLICT (cve_id, package_name, distro_name) DO UPDATE SET
    fixed_version = EXCLUDED.fixed_version,
    repository_version = EXCLUDED.repository_version,
    priority_level = EXCLUDED.priority_level,
    priority_color = EXCLUDED.priority_color,
    current_status = EXCLUDED.current_status,
    description = EXCLUDED.description,
    last_modified = NOW();

DELETE FROM debian_cve d
WHERE d.distro_name IN (SELECT DISTINCT distro_name FROM cve_staging)
  AND NOT EXISTS (
      SELECT 1 FROM cve_staging s
      WHERE s.cve_id = d.cve_id AND s.package_name = d.package_name AND s.distro_name = d.distro_name);

INSERT INTO cve_meta (id, last_update, record_count, distros)
SELECT 1, NOW(), COUNT(*), ARRAY_AGG(DISTINCT distro_name) FROM cve_staging
ON CONFLICT (id) DO UPDATE SET
    last_update = EXCLUDED.last_update,
    record_count = EXCLUDED.record_count,
    distros = EXCLUDED.distros;
COMMIT;
ANALYZE debian_cve;
EOSQL
then
    echo "✅ Import abgeschlossen."
else
    echo "❌ FATALER FEHLER: Datenbank-Import fehlgeschlagen (Rollback)."
    exit 1
fi

echo "======================================================================"
echo "✨ $(date '+%F %T') CVE-Update erfolgreich beendet."
echo "======================================================================"
