# 🛠️ DPM – Debian Patch Management

Ein simples, zentrales Patchmanagement-System für Debian-Server.

![DPM Screenshot](https://github.com/bmetallica/dpm/blob/main/utils/sc.png)

---


💻 Kernfunktionen und Systemzustand

  * Zentrale Zustandsübersicht: Dashboard zur gleichzeitigen Anzeige aller registrierten Server.

  * Update-Erkennung: Automatische Ermittlung der Anzahl und Liste der verfügbaren Paket-Updates (apt list --upgradable) via SSH.

  * Wichtige Systemmetriken: Erfassung von Host-Informationen (System-OS) und freiem Root-Speicherplatz.

  * Einfache SSH-WEB Konsole zur verbindung auf die Zielsysteme

<br>

⏰ Zeitsteuerung und Automatisierung

  * Flexible Zeitplanung: Frei wählbare Scheduling-Typen für die automatische Datenerfassung (stündlich [default], täglich, wöchentlich).
<br>

🛡️ SSH-Management und Sicherheit

  * One-Line-Bootstrap (grund.sh): Bereitstellung eines einfachen curl-Befehls zum schnellen Hinzufügen neuer Server und zur initialen Systemvorbereitung.

  * Automatisierter Key-Transfer: Das System kopiert den SSH Public Key automatisch auf den Zielserver, um die Grundlage für passwortloses Management zu schaffen.

  * Passwort-Härtung: Sofortige und automatische Änderung des SSH-Passworts auf dem Zielserver zu einem zufälligen, kryptografisch sicheren Wert nach erfolgreichem Key-Transfer.

  * Automatische Einstufung von Aktualisierungsdringlichkeit in 3 Stufen, auf grundlage der CVEs von security-tracker.debian.org

| Prioritätslevel | Visuelle Bedeutung | Beschreibung |
| :---: | :---: | :--- |
| **HIGH** | &#x1F534; **ROT** | **Hohes Risiko.** Erfordert sofortige Aufmerksamkeit und Behebung. |
| **MEDIUM** | &#x1F7E0; **ORANGE/GELB** | **Mittleres Risiko.** Sollte zeitnah behoben werden, kann zu signifikanten Problemen führen. |
| **END-OF-LIFE** (oder **EOL**) | &#x26AA; **GRAU** | **Ende der Lebensdauer.** Die betroffene Software oder Komponente wird nicht mehr gewartet oder erhält keine Sicherheitsupdates mehr. |

  
<br>

🚀 Update-Aktionen

  * Gezieltes Patching: Manuelle Auswahl und Installation einzelner Updates (apt install package-name).

  * Volles System-Upgrade: Startet das vollständige apt upgrade -y auf dem ausgewählten Server.

  * Live-Progress: Detaillierte Echtzeit-Übertragung der Installations- und Log-Ausgaben über WebSockets.
<br>

👥 Benutzer und Administration

  * Sichere Authentifizierung: Login mit Passwort-Hashing (bcrypt) und Session-Management.

  * Rollenbasierte Kontrolle (RBAC): Unterscheidung zwischen Administratoren und Standard-Benutzern.

  * User-Management: Administratives Erstellen und Löschen von Benutzerkonten.

  * Passwort-Änderung: Benutzer können ihr eigenes Passwort ändern.

<br><br>

---
## 🚀 Voraussetzungen

- Debian-Server mit **SSH**
- Im Netzwerk erreichbare **PostgreSQL-Datenbank**
- Installiertes **Node.js** inkl. `npm`
- SSH root Zugriff auf die Zielserver


---
## 📦 Schnellinstallation (als root)

```
wget https://raw.githubusercontent.com/bmetallica/dpm/refs/heads/main/install.sh
chmod +x install.sh
./install.sh
```
---


## 📦 Installation


### 1. Code herunterladen

```bash
cd /opt/
git clone https://github.com/bmetallica/dpm.git
```

### 2. `sshpass` `curl` und `jq` installieren

```bash
apt install sshpass curl jq expect build-essential python3
```

### 3. SSH-Schlüssel erstellen (als root)

```bash
ssh-keygen
```

### 4. Projekt vorbereiten

```bash
cd /opt/dpm/patch-management
npm init -y
npm install express pg ws bcrypt node-cron express-session node-pty xterm xterm-addon-fit ssh2
```

---

## 🗄️ PostgreSQL vorbereiten

1. Datenbank mit dem Namen `apt` anlegen.
2. Mit `psql` folgende SQL-Befehle ausführen:

```sql
CREATE SEQUENCE public.zustand_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

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
)

CREATE TABLE IF NOT EXISTS public.users
(
    id integer NOT NULL DEFAULT nextval('users_id_seq'::regclass),
    username character varying(50) COLLATE pg_catalog."default" NOT NULL,
    password_hash character varying(255) COLLATE pg_catalog."default" NOT NULL,
    is_admin boolean DEFAULT false,
    CONSTRAINT users_pkey PRIMARY KEY (id),
    CONSTRAINT users_username_key UNIQUE (username)
)

TABLESPACE pg_default;


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
)

TABLESPACE pg_default;

CREATE INDEX IF NOT EXISTS idx_debian_cve_id
    ON public.debian_cve USING btree
    (cve_id COLLATE pg_catalog."default" ASC NULLS LAST)
    WITH (fillfactor=100, deduplicate_items=True)
    TABLESPACE pg_default;

CREATE INDEX IF NOT EXISTS idx_debian_cve_pkg_status
    ON public.debian_cve USING btree
    (package_name COLLATE pg_catalog."default" ASC NULLS LAST, current_status COLLATE pg_catalog."default" ASC NULLS LAST)
    WITH (fillfactor=100, deduplicate_items=True)
    TABLESPACE pg_default;

CREATE INDEX IF NOT EXISTS idx_debian_cve_priority
    ON public.debian_cve USING btree
    (priority_level COLLATE pg_catalog."default" ASC NULLS LAST)
    WITH (fillfactor=100, deduplicate_items=True)
    TABLESPACE pg_default;


```

---

## 🔧 Konfiguration

### 1. SSH-Zugang konfigurieren 
Benutzername und Passwort für einen noch nicht existierenden Dienste-Benutzer eintragen <p>
<i>(Das Passwort wird nach der Initialisierung auf den Servern automatisch geändert)</i>

Datei `ssh.conf` anpassen:

```conf
user:"BENUTZERNAME"
password:"PASSWORT"
```

Datei `public/grund.sh` anpassen:
Hier müssen die selben Zugangsdaten wie in der ssh.conf hinterlegt werden!

### 2. Datenbank-Zugangsdaten in `index.js` eintragen.


## 🔄 Systemd-Dienst einrichten

```bash
mv /opt/dpm/utils/pm.service /etc/systemd/system/dpm.service
chmod 755 /etc/systemd/system/dpm.service
systemctl daemon-reload
systemctl start dpm
systemctl enable dpm
```

---

## 🛡️ CVE-Import
Datenbank mit aktuellen CVEś füllen und cron zum aktualisieren

```bash
chmod +x /opt/dpm/patch-management/cve.sh

#Initiales befüllen
/opt/dpm/patch-management/cve.sh

crontab zum aktualisieren der CVEs täglich um 1:00Uhr

crontab -e

* 1 * * * /opt/dpm/patch-management/cve.sh > /dev/null 2>&1 


```


---

## 🌐 Zugriff

Das Webinterface ist danach erreichbar unter:

```
http://localhost:3030
```

(Der Port kann in der Datei `index.js` angepasst werden.)
<br>
## Login
Der initiale Benutzername und das Passwort sind:

Benutzer: admin <br>
Passwort: admin

<br><br>
---
## Hinzufügen eines servers

Um dem Patchmanagement einen neuen Server hinzuzufügen:

1. Im Webfrontend anmelden
2. Button "Bootstrap kopieren" benutzen
3. Auf dem Ziel-Server via SSH als root den Bootstrap Befehl einfügen und ausführen
4. Button "Server hinzufügen" die Ziel IP-Adresse des Servers angeben
5. Über das Zahnrad (hinter der IP des neuen Servers) einen der Scheduling-Typen zur Sammlung der Daten auswählen

---


## 🎉 Viel Spaß mit diesem Projekt!

---

**Autor:** [bmetallica](https://github.com/bmetallica)
