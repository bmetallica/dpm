#!/bin/bash

# ======================================================================
# MASTER-SKRIPT: Download, Filterung & PostgreSQL-Import (FINAL OHNE CVSS)
# ======================================================================

# --- KONFIGURATION ---
URL="https://security-tracker.debian.org/tracker/data/json"
RAW_FILE="/tmp/cve_raw.json"
TEMP_JSON_FILE="/tmp/tmp_cve"
FLAT_FILE="/tmp/debian_cve_final_filtered.txt" 
TEMP_SQL_FILE="/tmp/debian_cve_inserts_final_$(date +%s).sql"

# PostgreSQL-Details
PG_USER="aptdb"
PG_PASSWORD="aptdb123" 
PG_HOST="localhost"
PG_DB="apt"

MIN_SIZE_KB=60000 

# cleanup-Funktion
cleanup() {
    echo "🧹 Führe Cleanup durch..."
    rm -f "$RAW_FILE" "$FLAT_FILE" "$TEMP_SQL_FILE"
}
trap cleanup EXIT

# Hilfsfunktion für psql-Aufrufe mit Passwort
run_psql() {
    local sql="$1"
    if [ -n "$PG_PASSWORD" ]; then
        PGPASSWORD="$PG_PASSWORD" psql -h "$PG_HOST" -U "$PG_USER" -d "$PG_DB" -c "$sql"
    else
        psql -h "$PG_HOST" -U "$PG_USER" -d "$PG_DB" -c "$sql"
    fi
}

run_psql_file() {
    local file="$1"
    if [ -n "$PG_PASSWORD" ]; then
        PGPASSWORD="$PG_PASSWORD" psql -h "$PG_HOST" -U "$PG_USER" -d "$PG_DB" -f "$file"
    else
        psql -h "$PG_HOST" -U "$PG_USER" -d "$PG_DB" -f "$file"
    fi
}

echo "======================================================================"
echo "🚀 STARTE FINALEN DEBIAN CVE-UPDATE-PROZESS (Gefiltert, OHNE CVSS)"
echo "======================================================================"

# --- 1. DOWNLOAD (Erster Download oder Nutzung von HH) ---
if [ ! -f "$TEMP_JSON_FILE" ]; then
    echo "--- 1. Download der 61MB Rohdaten (Robust) ---"
    while true; do
        rm -f "$RAW_FILE"
        if curl -sS --fail "$URL" -o "$RAW_FILE"; then
            FILE_SIZE=$(stat -c%s "$RAW_FILE" 2>/dev/null || echo 0)
            if [ "$FILE_SIZE" -ge "$MIN_SIZE_KB" ]; then
                echo "✅ Download erfolgreich. Größe: $(numfmt --to=iec --suffix=B $FILE_SIZE)"
                cat "$RAW_FILE" | jq > "$TEMP_JSON_FILE"
                break
            else
                echo "⚠ Datei zu klein. Versuche es in 10s erneut..."
            fi
        else
            echo "❌ Download fehlgeschlagen. Warte 10s..."
        fi
        sleep 10
    done
fi

# --- 2. POSTGRESQL SCHEMA-ANPASSUNG (Final, bereinigt) ---
echo "--- 2. PostgreSQL Schema-Anpassung ---"
# Behält die vorhandenen Spalten bei und fügt Versions- und Farbfelder hinzu.
# Die Spalte CVSS_SCORE bleibt in der DB, wird aber nicht mehr gefüllt/aktualisiert.

SCHEMA_SQL="
ALTER TABLE debian_cve ADD COLUMN IF NOT EXISTS distro_name VARCHAR(50);
ALTER TABLE debian_cve ADD COLUMN IF NOT EXISTS fixed_version VARCHAR(100);
ALTER TABLE debian_cve ADD COLUMN IF NOT EXISTS repository_version VARCHAR(100);
ALTER TABLE debian_cve ADD COLUMN IF NOT EXISTS priority_color VARCHAR(10); 
ALTER TABLE debian_cve DROP CONSTRAINT IF EXISTS debian_cve_pkey;
ALTER TABLE debian_cve ADD PRIMARY KEY (cve_id, package_name, distro_name);
"
if run_psql "$SCHEMA_SQL" > /dev/null 2>&1; then
    echo "✅ Schema erfolgreich aktualisiert."
else
    echo "❌ FEHLER: Schema-Anpassung fehlgeschlagen."
    exit 1
fi

# ----------------------------------------------------------------------
# SCHRITT 3: JSON-VERARBEITUNG OHNE CVSS
# ----------------------------------------------------------------------
echo "--- 3. JSON-Verarbeitung (Filterung & Versionen, OHNE CVSS) ---"

# Der finale, robuste Filter
jq -r '
    to_entries[] as $pkg_entry | 
    select($pkg_entry.value | type == "object") | 
    $pkg_entry.key as $pkg_name |
    $pkg_entry.value | to_entries[] |
    .key as $cve_id | 
    .value as $cve_data |
    $cve_data.releases | to_entries[] as $release_entry | 
    $release_entry.key as $distro_name | $release_entry.value as $distro_data |
    
    ($distro_data.urgency // "") as $urgency | 
    select($urgency | IN("high", "medium", "end-of-life")) |
    
    {
        cve_id: $cve_id,
        package_name: $pkg_name,
        distro_name: $distro_name,
        # CVSS_SCORE ENTFERNT
        fixed_version: ($distro_data.fixed_version // "NULL"),
        repository_version: ($distro_data.repositories[$distro_name] // "NULL"),
        urgency: $urgency,
        status: ($distro_data.status),
        description: ($cve_data.description)
    } | 
    "\(.cve_id)|\(.package_name)|\(.distro_name)|\(.fixed_version)|\(.repository_version)|\(.urgency)|\(.status)|\((.description // "") | gsub("\u0027"; ""))"
' "$TEMP_JSON_FILE" > "$FLAT_FILE"

if [ $? -eq 0 ]; then
    RECORD_COUNT=$(wc -l "$FLAT_FILE" | awk '{print $1}')
    echo "✅ jq-Verarbeitung erfolgreich abgeschlossen."
    echo "    Datensätze in $FLAT_FILE: $RECORD_COUNT (final gefiltert)."
else
    echo "❌ FATALER FEHLER: jq-Verarbeitung fehlgeschlagen."
    exit 1
fi

# ----------------------------------------------------------------------
# SCHRITT 4: DATEN-IMPORT OHNE CVSS
# ----------------------------------------------------------------------
echo "--- 4. Bulk-Import in PostgreSQL (OHNE CVSS) ---"

echo "BEGIN;" > "$TEMP_SQL_FILE"

# Lese 7 Spalten ein: cve_id|package_name|distro_name|fixed_version|repository_version|urgency|current_status|description
while IFS='|' read -r cve_id package_name distro_name fixed_version repository_version urgency current_status description; do
    
    # Farbzuweisung wie besprochen
    priority_color="GREEN" 
    case "$urgency" in
        "high")
            priority_color="RED"
            ;;
        "medium")
            priority_color="ORANGE"
            ;;
        "end-of-life")
            priority_color="GRAY"
            ;;
    esac
    
    description_escaped=$(echo "$description" | sed "s/'/''/g")
    
    # INSERT-Statement: Spalte cvss_score wird ausgelassen
    cat << EOF >> "$TEMP_SQL_FILE"
INSERT INTO debian_cve (cve_id, package_name, distro_name, fixed_version, repository_version, priority_level, priority_color, current_status, description, last_modified) 
VALUES ('$cve_id', '$package_name', '$distro_name', '$fixed_version', '$repository_version', '$urgency', '$priority_color', '$current_status', '$description_escaped', NOW()) 
ON CONFLICT (cve_id, package_name, distro_name) DO UPDATE SET 
fixed_version = EXCLUDED.fixed_version,
repository_version = EXCLUDED.repository_version,
priority_level = EXCLUDED.priority_level,
priority_color = EXCLUDED.priority_color,
current_status = EXCLUDED.current_status, 
description = EXCLUDED.description, 
last_modified = NOW();
EOF

done < "$FLAT_FILE"

echo "COMMIT;" >> "$TEMP_SQL_FILE"

echo "⚙ Lade $RECORD_COUNT Datensätze in die Datenbank..."

if run_psql_file "$TEMP_SQL_FILE" > /dev/null 2>&1; then
    echo "✅ Erfolgreich: Import abgeschlossen."
else
    echo "❌ FATALER FEHLER: Datenbank-Import fehlgeschlagen."
    exit 1
fi

echo "======================================================================"
echo "✨ CVE-Update Prozess erfolgreich beendet."
echo "======================================================================"
