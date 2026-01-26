#!/bin/bash
cd /opt/dpm/patch-management
# DPM Update Script - Lädt neue Versionen herunter und sichert alte Konfiguration
# Verwendung: sudo bash update.sh

set -e

# ===== KONFIGURATION =====
GITHUB_RAW_URL="https://raw.githubusercontent.com/bmetallica/dpm/refs/heads/main/patch-management"
BACKUP_DIR="./backups"
BACKUP_TIMESTAMP=$(date +%Y%m%d_%H%M%S)
SERVICE_NAME="pm"

# Farben für Output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# ===== FUNKTIONEN =====

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[FEHLER]${NC} $1"
}

# Prüfe ob Skript als root läuft
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "Dieses Skript muss als root ausgeführt werden!"
        exit 1
    fi
}

# Erstelle Backup-Verzeichnis
create_backup_dir() {
    if [[ ! -d "$BACKUP_DIR" ]]; then
        mkdir -p "$BACKUP_DIR"
        print_success "Backup-Verzeichnis erstellt: $BACKUP_DIR"
    fi
}

# Sichere alte Dateien
backup_files() {
    print_info "Sichere alte Dateien..."
    
    local files=("index.js" "public/index.html" "public/styles.css")
    
    for file in "${files[@]}"; do
        if [[ -f "$file" ]]; then
            local backup_file="$BACKUP_DIR/${file//\//_}_${BACKUP_TIMESTAMP}.bak"
            cp "$file" "$backup_file"
            print_success "Gesichert: $file → $backup_file"
        else
            print_warning "Datei nicht gefunden: $file (wird übersprungen)"
        fi
    done
}

# Extrahiere Konfigurationswerte aus altem index.js
extract_config() {
    print_info "Extrahiere Konfigurationswerte aus altem index.js..."
    
    local old_index="index.js"
    
    if [[ ! -f "$old_index" ]]; then
        print_error "index.js nicht gefunden!"
        return 1
    fi
    
    # Extrahiere ENABLE_LOGIN
    ENABLE_LOGIN=$(grep -oP "const ENABLE_LOGIN = \K(true|false)" "$old_index" || echo "true")
    print_success "ENABLE_LOGIN extrahiert: $ENABLE_LOGIN"
    
    # Extrahiere Datenbankverbindung (Pool-Konfiguration)
    DB_USER=$(grep -oP "user: '['\"]?\K[^'\"]*" "$old_index" | head -1)
    DB_HOST=$(grep -oP "host: '['\"]?\K[^'\"]*" "$old_index" | head -1)
    DB_DATABASE=$(grep -oP "database: '['\"]?\K[^'\"]*" "$old_index" | head -1)
    DB_PASSWORD=$(grep -oP "password: '['\"]?\K[^'\"]*" "$old_index" | head -1)
    DB_PORT=$(grep -oP "port: \K[0-9]*" "$old_index" | head -1)
    
    # Setze Defaults falls nicht gefunden
    DB_USER=${DB_USER:-"apt4auto"}
    DB_HOST=${DB_HOST:-"localhost"}
    DB_DATABASE=${DB_DATABASE:-"apt"}
    DB_PASSWORD=${DB_PASSWORD:-"apt4auto"}
    DB_PORT=${DB_PORT:-"5432"}
    
    print_success "Datenbankverbindung extrahiert:"
    echo "  - User: $DB_USER"
    echo "  - Host: $DB_HOST"
    echo "  - Database: $DB_DATABASE"
    echo "  - Port: $DB_PORT"
}

# Lade neue index.js herunter
download_new_index() {
    print_info "Lade neue index.js von GitHub herunter..."
    
    local temp_file="/tmp/index_new.js"
    
    if ! curl -sS -f -o "$temp_file" "${GITHUB_RAW_URL}/index.js"; then
        print_error "Fehler beim Herunterladen von index.js!"
        return 1
    fi
    
    if [[ ! -f "$temp_file" ]] || [[ ! -s "$temp_file" ]]; then
        print_error "Heruntergeladene index.js ist leer!"
        return 1
    fi
    
    print_success "index.js heruntergeladen"
    
    # Ersetze Datenbankverbindung in neuer Datei
    apply_database_config "$temp_file"
    
    # Ersetze ENABLE_LOGIN in neuer Datei
    apply_enable_login "$temp_file"
    
    # Kopiere neue Datei
    cp "$temp_file" "index.js"
    rm "$temp_file"
    print_success "index.js aktualisiert"
}

# Wende Datenbankverbindung auf neue index.js an
apply_database_config() {
    local file="$1"
    
    if [[ ! -f "$file" ]]; then
        print_error "Datei nicht gefunden: $file"
        return 1
    fi
    
    print_info "Wende Datenbankverbindung an..."
    
    # Ersetze Pool-Konfiguration
    sed -i "s/user: '[^']*'/user: '$DB_USER'/g" "$file"
    sed -i "s/host: '[^']*'/host: '$DB_HOST'/g" "$file"
    sed -i "s/database: '[^']*'/database: '$DB_DATABASE'/g" "$file"
    sed -i "s/password: '[^']*'/password: '$DB_PASSWORD'/g" "$file"
    sed -i "s/port: [0-9]*/port: $DB_PORT/g" "$file"
    
    print_success "Datenbankverbindung angewendet"
}

# Wende ENABLE_LOGIN auf neue index.js an
apply_enable_login() {
    local file="$1"
    
    if [[ ! -f "$file" ]]; then
        print_error "Datei nicht gefunden: $file"
        return 1
    fi
    
    print_info "Wende ENABLE_LOGIN an..."
    
    sed -i "s/const ENABLE_LOGIN = \(true\|false\)/const ENABLE_LOGIN = $ENABLE_LOGIN/" "$file"
    
    print_success "ENABLE_LOGIN angewendet: $ENABLE_LOGIN"
}

# Lade neue index.html herunter
download_new_html() {
    print_info "Lade neue index.html von GitHub herunter..."
    
    local temp_file="/tmp/index_new.html"
    
    if ! curl -sS -f -o "$temp_file" "${GITHUB_RAW_URL}/public/index.html"; then
        print_error "Fehler beim Herunterladen von index.html!"
        return 1
    fi
    
    if [[ ! -f "$temp_file" ]] || [[ ! -s "$temp_file" ]]; then
        print_error "Heruntergeladene index.html ist leer!"
        return 1
    fi
    
    cp "$temp_file" "public/index.html"
    rm "$temp_file"
    print_success "index.html aktualisiert"
}

# Lade neue styles.css herunter
download_new_css() {
    print_info "Lade neue styles.css von GitHub herunter..."
    
    local temp_file="/tmp/styles_new.css"
    
    if ! curl -sS -f -o "$temp_file" "${GITHUB_RAW_URL}/public/styles.css"; then
        print_error "Fehler beim Herunterladen von styles.css!"
        return 1
    fi
    
    if [[ ! -f "$temp_file" ]] || [[ ! -s "$temp_file" ]]; then
        print_error "Heruntergeladene styles.css ist leer!"
        return 1
    fi
    
    cp "$temp_file" "public/styles.css"
    rm "$temp_file"
    print_success "styles.css aktualisiert"
}

# Neustart des Services
restart_service() {
    print_info "Starte DPM-Service neu..."
    
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        systemctl restart "$SERVICE_NAME"
        print_success "Service neugestartet"
    else
        print_warning "Service nicht aktiv. Überspringe Neustart."
    fi
}

# Zeige Zusammenfassung
show_summary() {
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}  Update erfolgreich abgeschlossen!${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    echo "Aktualisierte Dateien:"
    echo "  ✓ patch-management/index.js"
    echo "  ✓ patch-management/public/index.html"
    echo "  ✓ patch-management/public/styles.css"
    echo ""
    echo "Sicherungen (falls Rollback nötig):"
    echo "  → $BACKUP_DIR/"
    echo ""
    echo "Konfiguration beibehalten:"
    echo "  ✓ Datenbankverbindung"
    echo "  ✓ ENABLE_LOGIN = $ENABLE_LOGIN"
    echo ""
    echo -e "${YELLOW}Hinweis:${NC} Die Anwendung wurde automatisch neu gestartet."
    echo ""
}

# ===== HAUPTPROGRAMM =====

main() {
    echo -e "${BLUE}"
    echo "╔════════════════════════════════════════╗"
    echo "║   DPM Update Script                    ║"
    echo "║   Debian Patch Management              ║"
    echo "╚════════════════════════════════════════╝"
    echo -e "${NC}"
    echo ""
    
    check_root
    
    # Wechsle ins patch-management Verzeichnis
    cd "$(dirname "$(readlink -f "$0")")" || exit 1
    
    print_info "Arbeitsverzeichnis: $(pwd)"
    echo ""
    
    # Führe Update-Schritte aus
    create_backup_dir
    backup_files
    echo ""
    extract_config
    echo ""
    download_new_index
    download_new_html
    download_new_css
    echo ""
    restart_service
    echo ""
    show_summary
}

# Fehlerbehandlung
trap 'print_error "Update abgebrochen!"; exit 1' ERR

# Starte Main
main
