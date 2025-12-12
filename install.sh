#!/bin/bash

#######################################################
# DPM - Debian Patch Management Installation Script
# Für Debian-Systeme
#######################################################

set -e

# Farben für Ausgabe
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging-Funktion
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Prüfe Root-Rechte
if [ "$EUID" -ne 0 ]; then 
    log_error "Dieses Script muss als root ausgeführt werden!"
    exit 1
fi

# Banner
clear
echo "============================================"
echo "  DPM - Debian Patch Management Installer"
echo "============================================"
echo ""

#######################################################
# Benutzer-Eingaben abfragen
#######################################################

log_info "Schritt 1/7: Konfigurationsdaten abfragen"
echo ""

# PostgreSQL Konfiguration
read -p "PostgreSQL Host (z.B. localhost): " PG_HOST
PG_HOST=${PG_HOST:-localhost}

read -p "PostgreSQL Port (Standard: 5432): " PG_PORT
PG_PORT=${PG_PORT:-5432}

read -p "PostgreSQL Datenbank-Name (Standard: apt): " PG_DB
PG_DB=${PG_DB:-apt}

read -p "PostgreSQL Benutzername: " PG_USER

while true; do
    read -sp "PostgreSQL Passwort: " PG_PASS
    echo ""
    read -sp "PostgreSQL Passwort wiederholen: " PG_PASS2
    echo ""
    if [ "$PG_PASS" = "$PG_PASS2" ]; then
        break
    else
        log_error "Passwörter stimmen nicht überein. Bitte erneut eingeben."
    fi
done

echo ""
# SSH Dienst-Benutzer
read -p "SSH Dienst-Benutzername (für Ziel-Server): " SSH_USER

while true; do
    read -sp "SSH Dienst-Passwort (wird später automatisch geändert): " SSH_PASS
    echo ""
    read -sp "SSH Dienst-Passwort wiederholen: " SSH_PASS2
    echo ""
    if [ "$SSH_PASS" = "$SSH_PASS2" ]; then
        break
    else
        log_error "Passwörter stimmen nicht überein. Bitte erneut eingeben."
    fi
done

echo ""
# Webserver Port
read -p "Webserver Port (Standard: 3030): " WEB_PORT
WEB_PORT=${WEB_PORT:-3030}

echo ""
log_info "Konfiguration abgeschlossen!"
sleep 2

#######################################################
# System aktualisieren
#######################################################

log_info "Schritt 2/7: System aktualisieren"
apt update
apt upgrade -y

#######################################################
# Abhängigkeiten installieren
#######################################################

log_info "Schritt 3/7: Abhängigkeiten installieren"

# Prüfe ob PostgreSQL lokal installiert werden soll
if [ "$PG_HOST" = "localhost" ] || [ "$PG_HOST" = "127.0.0.1" ]; then
    log_info "Installiere PostgreSQL lokal..."
    apt install -y postgresql postgresql-contrib
    
    # Starte PostgreSQL
    systemctl start postgresql
    systemctl enable postgresql
    
    # Erstelle Datenbank und Benutzer
    log_info "Erstelle Datenbank und Benutzer..."
    sudo -u postgres psql -c "CREATE DATABASE $PG_DB;" 2>/dev/null || log_warn "Datenbank existiert bereits"
    sudo -u postgres psql -c "CREATE USER $PG_USER WITH PASSWORD '$PG_PASS';" 2>/dev/null || log_warn "Benutzer existiert bereits"
    sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE $PG_DB TO $PG_USER;"
    sudo -u postgres psql -d $PG_DB -c "GRANT ALL ON SCHEMA public TO $PG_USER;"
fi

# Installiere weitere Abhängigkeiten
log_info "Installiere weitere Pakete..."
apt install -y curl git sshpass jq expect build-essential python3

# Prüfe ob Node.js installiert ist
if ! command -v node &> /dev/null; then
    log_info "Installiere Node.js..."
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
    apt install -y nodejs
else
    log_info "Node.js ist bereits installiert ($(node -v))"
fi

#######################################################
# DPM herunterladen und einrichten
#######################################################

log_info "Schritt 4/7: DPM herunterladen"

# Entferne altes Verzeichnis falls vorhanden
if [ -d "/opt/dpm" ]; then
    log_warn "Altes DPM-Verzeichnis gefunden. Erstelle Backup..."
    mv /opt/dpm /opt/dpm.backup.$(date +%Y%m%d_%H%M%S)
fi

cd /opt/
git clone https://github.com/bmetallica/dpm.git
cd /opt/dpm/patch-management

# NPM Pakete installieren
log_info "Installiere NPM-Pakete..."
npm init -y
npm install express pg ws bcrypt node-cron express-session node-pty xterm xterm-addon-fit ssh2

#######################################################
# SSH-Schlüssel erstellen
#######################################################

log_info "Schritt 5/7: SSH-Schlüssel erstellen"

if [ ! -f "/root/.ssh/id_rsa" ]; then
    ssh-keygen -t rsa -b 4096 -f /root/.ssh/id_rsa -N ""
    log_info "SSH-Schlüssel wurde erstellt"
else
    log_warn "SSH-Schlüssel existiert bereits"
fi

#######################################################
# Konfigurationsdateien anpassen
#######################################################

log_info "Schritt 6/7: Konfigurationsdateien anpassen"

# ssh.conf erstellen/anpassen
cat > /opt/dpm/patch-management/ssh.conf << EOF
user:"$SSH_USER"
password:"$SSH_PASS"
EOF

log_info "ssh.conf wurde erstellt"

# index.js Datenbank-Konfiguration anpassen
log_info "Passe Datenbank-Konfiguration in index.js an..."

# Suche nach der Zeile mit "const pool = new Pool({" und ersetze die Konfiguration
sed -i "/const pool = new Pool({/,/});/c\\
const pool = new Pool({\n\
  user: '$PG_USER',\n\
  host: '$PG_HOST',\n\
  database: '$PG_DB',\n\
  password: '$PG_PASS',\n\
  port: $PG_PORT,\n\
});" /opt/dpm/patch-management/index.js

# Port in index.js anpassen
sed -i "s/const PORT = [0-9]*;/const PORT = $WEB_PORT;/" /opt/dpm/patch-management/index.js

log_info "index.js wurde konfiguriert"

# grund.sh anpassen (Bootstrap-Script)
log_info "Passe grund.sh an..."
sed -i "s/USER_NAME=\"[^\"]*\"/USER_NAME=\"$SSH_USER\"/" /opt/dpm/patch-management/public/grund.sh
sed -i "s/USER_PASS=\"[^\"]*\"/USER_PASS=\"$SSH_PASS\"/" /opt/dpm/patch-management/public/grund.sh

#######################################################
# Datenbank initialisieren
#######################################################

log_info "Initialisiere Datenbank..."

export PGPASSWORD="$PG_PASS"

# Erstelle Tabellen
psql -h "$PG_HOST" -p "$PG_PORT" -U "$PG_USER" -d "$PG_DB" << 'EOSQL'

-- Sequence für zustand
CREATE SEQUENCE IF NOT EXISTS public.zustand_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

-- Sequence für users
CREATE SEQUENCE IF NOT EXISTS public.users_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

-- Tabelle zustand
CREATE TABLE IF NOT EXISTS public.zustand
(
    id integer NOT NULL DEFAULT nextval('zustand_id_seq'::regclass),
    server character varying(15) COLLATE pg_catalog."default" NOT NULL,
    sys character varying(255) COLLATE pg_catalog."default" NOT NULL,
    pu character varying(3) COLLATE pg_catalog."default" NOT NULL,
    ul text COLLATE pg_catalog."default",
    root_free character varying(10) COLLATE pg_catalog."default" NOT NULL,
    last_run timestamp with time zone NOT NULL,
    zus character varying(255) COLLATE pg_catalog."default",
    komment character varying(255) COLLATE pg_catalog."default",
    schedule_type text COLLATE pg_catalog."default",
    schedule_time text COLLATE pg_catalog."default",
    CONSTRAINT zustand_pkey PRIMARY KEY (id),
    CONSTRAINT zustand_server_key UNIQUE (server)
);

-- Tabelle users
CREATE TABLE IF NOT EXISTS public.users
(
    id integer NOT NULL DEFAULT nextval('users_id_seq'::regclass),
    username character varying(50) COLLATE pg_catalog."default" NOT NULL,
    password_hash character varying(255) COLLATE pg_catalog."default" NOT NULL,
    is_admin boolean DEFAULT false,
    CONSTRAINT users_pkey PRIMARY KEY (id),
    CONSTRAINT users_username_key UNIQUE (username)
);

-- Tabelle debian_cve
CREATE TABLE IF NOT EXISTS public.debian_cve
(
    cve_id character varying(50) COLLATE pg_catalog."default" NOT NULL,
    package_name character varying(100) COLLATE pg_catalog."default" NOT NULL,
    distro_name character varying(50) COLLATE pg_catalog."default" NOT NULL,
    fixed_version character varying(100) COLLATE pg_catalog."default",
    repository_version character varying(100) COLLATE pg_catalog."default",
    current_status character varying(50) COLLATE pg_catalog."default" NOT NULL,
    priority_level character varying(50) COLLATE pg_catalog."default",
    priority_color character varying(10) COLLATE pg_catalog."default",
    description text COLLATE pg_catalog."default",
    last_modified timestamp with time zone NOT NULL DEFAULT now(),
    created_at timestamp with time zone NOT NULL DEFAULT now(),
    CONSTRAINT debian_cve_pkey PRIMARY KEY (cve_id, package_name, distro_name)
);

-- Indices für debian_cve
CREATE INDEX IF NOT EXISTS idx_debian_cve_id
    ON public.debian_cve USING btree
    (cve_id COLLATE pg_catalog."default" ASC NULLS LAST);

CREATE INDEX IF NOT EXISTS idx_debian_cve_pkg_status
    ON public.debian_cve USING btree
    (package_name COLLATE pg_catalog."default" ASC NULLS LAST, current_status COLLATE pg_catalog."default" ASC NULLS LAST);

CREATE INDEX IF NOT EXISTS idx_debian_cve_priority
    ON public.debian_cve USING btree
    (priority_level COLLATE pg_catalog."default" ASC NULLS LAST);

EOSQL

unset PGPASSWORD

log_info "Datenbank-Tabellen wurden erstellt"

#######################################################
# Systemd Service einrichten
#######################################################

log_info "Schritt 7/7: Systemd Service einrichten"

# Service-Datei erstellen
cat > /etc/systemd/system/dpm.service << EOF
[Unit]
Description=DPM - Debian Patch Management
After=network.target postgresql.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/dpm/patch-management
ExecStart=/usr/bin/node /opt/dpm/patch-management/index.js
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

chmod 644 /etc/systemd/system/dpm.service

# Service aktivieren und starten
systemctl daemon-reload
systemctl enable dpm
systemctl start dpm

#######################################################
# CVE-Import einrichten
#######################################################

log_info "Richte CVE-Import ein..."

chmod +x /opt/dpm/patch-management/cve.sh

# Crontab für CVE-Update einrichten
(crontab -l 2>/dev/null | grep -v "cve.sh"; echo "0 1 * * * /opt/dpm/patch-management/cve.sh > /dev/null 2>&1") | crontab -

log_info "CVE-Import wurde konfiguriert (läuft täglich um 1:00 Uhr)"

# Initiales CVE-Import im Hintergrund starten
log_info "Starte initialen CVE-Import (läuft im Hintergrund)..."
nohup /opt/dpm/patch-management/cve.sh > /var/log/dpm-cve-init.log 2>&1 &

#######################################################
# Firewall-Hinweis
#######################################################

if command -v ufw &> /dev/null; then
    log_warn "UFW Firewall erkannt. Port $WEB_PORT muss ggf. freigegeben werden:"
    echo "      ufw allow $WEB_PORT/tcp"
fi

if command -v firewall-cmd &> /dev/null; then
    log_warn "Firewalld erkannt. Port $WEB_PORT muss ggf. freigegeben werden:"
    echo "      firewall-cmd --permanent --add-port=$WEB_PORT/tcp"
    echo "      firewall-cmd --reload"
fi

#######################################################
# Abschluss
#######################################################

echo ""
echo "============================================"
log_info "Installation erfolgreich abgeschlossen!"
echo "============================================"
echo ""
echo "DPM läuft nun auf: http://$(hostname -I | awk '{print $1}'):$WEB_PORT"
echo ""
echo "Standard Login:"
echo "  Benutzername: admin"
echo "  Passwort: admin"
echo ""
echo "WICHTIG: Ändere das Admin-Passwort nach dem ersten Login!"
echo ""
echo "Service-Status prüfen:"
echo "  systemctl status dpm"
echo ""
echo "Logs anzeigen:"
echo "  journalctl -u dpm -f"
echo ""
echo "CVE-Import Log:"
echo "  tail -f /var/log/dpm-cve-init.log"
echo ""
echo "Konfiguration:"
echo "  - PostgreSQL: $PG_HOST:$PG_PORT/$PG_DB"
echo "  - SSH User: $SSH_USER"
echo "  - Webserver Port: $WEB_PORT"
echo ""
log_info "Fertig! Viel Erfolg mit DPM!"
echo ""
