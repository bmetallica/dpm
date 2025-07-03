# 🛠️ DPM – Debian Patch Management

Ein simples, zentrales Patchmanagement-System für Debian-Server im geschützten Homelab.

![DPM Screenshot](https://github.com/bmetallica/dpm/blob/main/utils/sc.png)

---

## 🚀 Voraussetzungen

- Debian-Server mit **SSH**
- Im Netzwerk erreichbare **PostgreSQL-Datenbank**
- Installiertes **Node.js** inkl. `npm`
- Auf allen Zielsystemen:
  - Ein Benutzer mit APT-Rechten und SSH-Zugang
  - Eintrag in der Datei `ssh.conf`

---

## 📦 Installation

### 1. Code herunterladen

```bash
cd /opt/
git clone https://github.com/bmetallica/dpm.git
```

### 2. `sshpass` installieren

```bash
apt install sshpass
```

### 3. SSH-Schlüssel erstellen (als root)

```bash
ssh-keygen
```

### 4. Projekt vorbereiten

```bash
cd /opt/dpm/patch-management
npm init -y
npm install express pg body-parser ws
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

CREATE TABLE public.zustand (
    id integer NOT NULL DEFAULT nextval('zustand_id_seq'::regclass),
    server character varying(15) NOT NULL,
    sys character varying(255) NOT NULL,
    pu character varying(3) NOT NULL,
    ul text,
    root_free character varying(10) NOT NULL,
    last_run timestamp NOT NULL,
    zus character varying(255),
    komment character varying(255),
    CONSTRAINT zustand_pkey PRIMARY KEY (id),
    CONSTRAINT zustand_server_key UNIQUE (server)
);
```

---

## 🔧 Konfiguration

### 1. SSH-Zugang konfigurieren

Datei `ssh.conf` anpassen:

```conf
benutzername
passwort
```

### 2. Datenbank-Zugangsdaten in `index.js` eintragen.

### 3. `patch.sh` auf den Zielsystemen einrichten

- Datei `/opt/dpm/utils/patch.sh` nach `/local/` auf dem Zielserver kopieren
- In `patch.sh` die Datenbank-Zugangsdaten anpassen
- Cronjob zum regelmäßigen Ausführen einrichten:

```bash
crontab -e
```

```cron
0 * * * * /local/patch.sh
```

---

## 🔄 Systemd-Dienst einrichten

```bash
mv /opt/dpm/utils/pm.service /etc/systemd/system/
chmod 755 /etc/systemd/system/pm.service
systemctl daemon-reload
systemctl start pm
systemctl enable pm
```

---

## 🌐 Zugriff

Das Webinterface ist danach erreichbar unter:

```
http://localhost:3000
```

(Der Port kann in der Datei `index.js` angepasst werden.)

---

## 🎉 Viel Spaß mit diesem Projekt!

---

**Autor:** [bmetallica](https://github.com/bmetallica)
