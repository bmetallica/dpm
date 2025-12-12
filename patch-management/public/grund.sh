#!/bin/bash

# Stellen Sie sicher, dass das Skript als root ausgeführt wird
if [[ $EUID -ne 0 ]]; then
   echo "Dieses Skript muss als root oder mit sudo ausgeführt werden."
   exit 1
fi

USER_NAME="USER"
USER_PASS="PASSWORT"



SUDO_CONFIG_FILE="/etc/sudoers.d/90-${USER_NAME}-nopasswd"
ENV_FILE="/etc/environment"


apt install sudo -y

# --- USER SETUP ---

echo "--- 1. Benutzer-Setup für '$USER_NAME' ---"

# 1. Benutzer anlegen
echo "👉 Erstelle den Benutzer '$USER_NAME'..."
useradd -m -s /bin/bash "$USER_NAME"

if [ $? -ne 0 ]; then
    echo "❌ Fehler beim Erstellen des Benutzers '$USER_NAME'. Beende Skript."
    exit 1
fi

# 2. Passwort festlegen
echo "🔒 Setze das Passwort für Benutzer '$USER_NAME'..."
echo "$USER_NAME:$USER_PASS" | chpasswd

# 3. sudo-Rechte ohne Passworteingabe hinzufügen
echo "🛡️ Konfiguriere 'sudo'-Rechte (NOPASSWD) für Benutzer '$USER_NAME'..."
echo "$USER_NAME ALL=(ALL) NOPASSWD: ALL" > "$SUDO_CONFIG_FILE"
chmod 0440 "$SUDO_CONFIG_FILE"

echo "✅ Benutzer '$USER_NAME' erfolgreich eingerichtet."

echo "---"
