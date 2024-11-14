#!/bin/bash

# PostgreSQL Credentials
PG_HOST="192.168.66.77"
PG_USER="postgres"
export PGPASSWORD="postgres"
PG_DATABASE="apt"

# Funktion zum Einfügen oder Aktualisieren von Daten in die PostgreSQL-Tabelle
insert_or_update_data() {
    local server_ip="$1"
    local debian_version="$2"
    local updates_possible="$3"
    local update_list="$4"
    local root_free="$5"
    local current_datetime="$(date +'%Y-%m-%d %H:%M:%S')"

    # SQL-Statement zum Einfügen oder Aktualisieren von Daten in die Tabelle
    psql -h "$PG_HOST" -U "$PG_USER" -d "$PG_DATABASE" -c "INSERT INTO zustand (server, sys, pu, ul, root_free, last_run) VALUES ('$server_ip', '$debian_version', '$updates_possible', '$update_list', '$root_free', '$current_datetime') ON CONFLICT (server) DO UPDATE SET sys='$debian_version', pu='$updates_possible', ul='$update_list', root_free='$root_free', last_run='$current_datetime';"
}

# Hauptskript

# Aktualisieren Sie die Paketliste
apt update
if ! command -v psql &> /dev/null
then
    echo "psql is not installed. Installing postgresql-client..."
    apt install -y postgresql-client
fi

if ! command -v lsb-release &> /dev/null
then
    echo "lsb-release is not installed. Installing postgresql-client..."
    apt install -y lsb-release
fi
# Erfassen von Systeminformationen
server_ip=$(hostname -I | awk '{print $1}')  # IP-Adresse des Servers
debian_version=$(lsb_release -ds)  # Aktuelle Debian-Version
update_output=$(apt list --upgradable 2>/dev/null |grep -v "Listing" |grep -v "Auflistung" 2>/dev/null)  # Ausgabe der möglichen Updates
updates_possible=$(apt list --upgradable 2>/dev/null |grep -v "Listing" |grep -v "Auflistung" 2>/dev/null | wc -l)  # Anzahl der möglichen Updates
update_list="$update_output"  # Liste der möglichen Updates
root_free=$(df -h / | awk 'NR==2 {print $4}')  # Freier Speicherplatz auf der Root-Partition

# Führen Sie die Funktion zum Einfügen oder Aktualisieren von Daten in die PostgreSQL-Tabelle aus

insert_or_update_data "$server_ip" "$debian_version" "$updates_possible" "$update_list" "$root_free"

echo "Daten erfolgreich in die PostgreSQL-Tabelle eingefügt oder aktualisiert."

