# dpm
simple central debian patchmanagement

Es handelt sich um ein kleines zentrales Patchmanagement für Debian Server im geschützten Homelab.

![Alternativtext](https://github.com/bmetallica/dpm/blob/main/utils/sc.png)


Voraussetzungen:
Ein Debian Server mit SSH, einer im Netzwerk erreichbaren PostgreSQL Datenbank und NodeJS incl. npm.

Installation:

1. Download nach /opt/ mit "git clone"

2. "apt install sshpass" 

3. SSH Schlüssel als root erstellen: "ssh-keygen"

4. cd /opt/patch-management

5. Nodeprojekt initiieren mit "npm init -y"

6. Abhängigkeiten installieren mit "npm install express pg body-parser ws"

7. Eine PostgreSQL Datenbank mit dem Namen "apt" anlegen

8. Mit psql in der Datenbank die Tabelle anlegen:
CREATE SEQUENCE public.zustand_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

CREATE TABLE public.zustand ( id integer NOT NULL DEFAULT nextval('zustand_id_seq'::regclass), server character varying(15) COLLATE pg_catalog."default" NOT NULL, sys character varying(255) COLLATE pg_catalog."default" NOT NULL, pu character varying(3) COLLATE pg_catalog."default" NOT NULL, ul text COLLATE pg_catalog."default", root_free character varying(10) COLLATE pg_catalog."default" NOT NULL, last_run timestamp without time zone NOT NULL, zus character varying(255) COLLATE pg_catalog."default", komment character varying(255) COLLATE pg_catalog."default", CONSTRAINT zustand_pkey PRIMARY KEY (id), CONSTRAINT zustand_server_key UNIQUE (server) ) WITH ( OIDS = FALSE ) TABLESPACE pg_default;

9. In der Datei ssh.conf den Benutzernamen und das Passwort des Users für den Remotezugriff auf die "Client-Server" eintragen.

10. In der Datei index.js den Benutzernamen und das Passwort der Datenbank anpassen

11. Die Datei /opt/utils/patch.sh auf den "Client-Server" in das Verzeichnis /local/ (falls erforderlich anlegen) kopieren und dort ebenfalls die Datenbankzugangsdaten anpassen

12. Auf dem "Client-Server" einen cronjob erstellen um die Datei patch.sh regelmäßig auszuführen


Erstellen eines Dienstes zum Starten des Patchmanagement

1. "mv /opt/utils/pm.service /etc/systemd/system/"

2. "chmod 777 /etc/systemd/system/pm.service"

3. "systemctl daemon-reload"

4. "systemctl start pm"

5. autostart
systemctl enable pm

Das Webinterfache sollte dann im Browser unter http://localhost:3000 erreichbar sein

Viel Spaß mit diesem Projekt
