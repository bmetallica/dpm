// index.js (Vollständige Version mit Cron-Jobs, Datenabruf und allen Endpunkten)

const express = require('express');
const { Pool } = require('pg');
const fs = require('fs');
const { exec, spawn } = require('child_process');
const WebSocket = require('ws');
const path = require('path');
const cron = require('node-cron');
const crypto = require('crypto'); // Für zufällige Passwörter
const os = require('os');
const { spawn: spawnPty } = require('node-pty');

const session = require('express-session');
const bcrypt = require('bcrypt');
const saltRounds = 10;

const app = express();
const port = 3030;

// ===== KONFIGURATION =====
const ENABLE_LOGIN = true; // Setze auf 'false', um Login zu deaktivieren und freien Zugriff zu ermöglichen
const DEFAULT_USERNAME = 'guest'; // Standard-Benutzername wenn Login deaktiviert ist

const GLOBAL_TIMEZONE = 'Europe/Berlin';
const GLOBAL_DATE_FORMAT = 'YYYY-MM-DD HH24:MI:SS'; // Standardformat

// PostgreSQL-Verbindung einrichten
const pool = new Pool({
  user: 'apt4auto',
  host: 'localhost',
  database: 'apt',
  password: 'apt4auto',
  port: 5432,
});


let sshuser = '';
let sshpass = '';
const cronJobs = {};

// Pfad zur Datei ssh.conf
const filePath = path.join(__dirname, 'ssh.conf');

// --- HILFSFUNKTIONEN FÜR AUTHENTIFIZIERUNG UND BEREINIGUNG (VOR MIDDLEWARE DEFINIEREN) ---

/**
 * Erstellt den initialen Admin-Benutzer, falls dieser noch nicht existiert.
 */
async function initializeAdminUser() {
    const adminUsername = 'admin';
    const adminPassword = 'admin';

    try {
        const checkUser = await pool.query('SELECT * FROM users WHERE username = $1', [adminUsername]);

        if (checkUser.rows.length === 0) {
            const passwordHash = await bcrypt.hash(adminPassword, saltRounds);
            await pool.query(
                'INSERT INTO users (username, password_hash, is_admin) VALUES ($1, $2, TRUE)',
                             [adminUsername, passwordHash]
            );
            console.log(`[AUTH] Initialer Admin-Benutzer '${adminUsername}' erstellt.`);
        } else {
            console.log(`[AUTH] Admin-Benutzer '${adminUsername}' existiert bereits.`);
        }
    } catch (error) {
        console.error('FEHLER beim Initialisieren des Admin-Benutzers:', error);
    }
}

/**
 * Middleware: Prüft, ob der Benutzer eingeloggt ist (wenn Login aktiviert ist).
 */
function requireLogin(req, res, next) {
    // Falls Login deaktiviert ist: Alle Anfragen erlauben und Standard-Session setzen
    if (!ENABLE_LOGIN) {
        if (!req.session.userId) {
            req.session.userId = -1; // Pseudo-ID für nicht authentifizierte Benutzer
            req.session.username = DEFAULT_USERNAME;
            req.session.isAdmin = false;
        }
        return next();
    }

    // Falls Login AKTIVIERT ist: Normale Authentifizierung durchführen
    // 1. ZULÄSSIGE, NICHT GESCHÜTZTE PFADE definieren:
    if (
        req.path === '/api/login' ||
        req.path.startsWith('/api/bootstrap/') ||
        req.path === '/login.html' ||
        req.path === '/' ||
        req.path === '/index.html'
    ) {
        return next();
    }

    // 2. Prüft, ob der Benutzer eine aktive Session hat
    if (req.session && req.session.userId) {
        return next();
    }

    // 3. Wenn nicht eingeloggt und nicht auf einem erlaubten Pfad: Umleiten
    if (req.path.startsWith('/api/')) {
        return res.status(401).json({ error: 'Nicht authentifiziert.' });
    }

    // Für alle anderen Routen (Frontend-Ressourcen) zur Anmeldeseite weiterleiten
    res.redirect('/login.html');
}





/**
 * Middleware: Prüft, ob der Benutzer Administrator ist.
 */
function requireAdmin(req, res, next) {
    // req.session.isAdmin muss durch requireLogin gesetzt worden sein
    if (req.session.isAdmin) {
        next(); // Admin ist berechtigt
    } else {
        // 403 Forbidden
        console.warn(`Zugriff verweigert: Benutzer ${req.session.username} ist kein Admin.`);
        res.status(403).json({ success: false, message: 'Zugriff nur für Administratoren.' });
    }
}

// ----------------------------------------------------------------------
// --- EXPRESS MIDDLEWARE KONFIGURATION (KRITISCHE REIHENFOLGE) ---
// ----------------------------------------------------------------------

// 1. Session-Middleware
app.use(session({
    secret: 'ein-sehr-geheimes-zufallspasswort-oder-key',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 24 * 60 * 60 * 1000 }
}));

// 2. Body Parser (Muss VOR ALLEN ROUTEN stehen, die req.body verwenden!)
app.use(express.json()); // Nutze den Express-internen Body-Parser
app.use(express.urlencoded({ extended: true })); // Optional, falls Form-Daten gesendet werden

// 3. Statische Dateien (Muss VOR requireLogin stehen, um Assets zu laden)
app.use(express.static('public'));
app.use('/node_modules', express.static('node_modules')); // Für xterm.js und andere Module

// 4. Login-Prüfung (Schützt alle nachfolgenden Routen)
app.use(requireLogin);

// ----------------------------------------------------------------------
// --- ENDE MIDDLEWARE ---
// ----------------------------------------------------------------------

// --- CRON-SCHEDULER UND SSH HILFSFUNKTIONEN (VOR ENDPUNKTEN) ---

function getCronString(type, time, day = '0') {
    if (type === 'hourly') {
        return '0 * * * *';
    }
    if (type === 'daily' && time) {
        const [hour, minute] = time.split(':');
        return `${minute} ${hour} * * *`;
    }
    if (type === 'weekly' && time) {
        const [hour, minute] = time.split(':');
        return `${minute} ${hour} * * ${day}`;
    }
    return null;
}

async function startScheduler() {
    console.log('Starte Patch-Management Scheduler...');
    for (const ip in cronJobs) {
        cronJobs[ip].stop();
        delete cronJobs[ip];
    }
    try {
        // Füge schedule_day Spalte hinzu, falls noch nicht vorhanden
        await pool.query(`
            ALTER TABLE zustand
            ADD COLUMN IF NOT EXISTS schedule_day text DEFAULT '0'
        `);
        
        // Füge is_offline Spalte hinzu, falls noch nicht vorhanden
        await pool.query(`
            ALTER TABLE zustand
            ADD COLUMN IF NOT EXISTS is_offline boolean DEFAULT false
        `);
        
        const result = await pool.query('SELECT server, schedule_type, schedule_time, schedule_day FROM zustand WHERE schedule_type IS NOT NULL');
        result.rows.forEach(row => {
            const cronString = getCronString(row.schedule_type, row.schedule_time, row.schedule_day);
            if (cronString) {
                console.log(`[CRON] Plane ${row.server} (${row.schedule_type}) mit Cron: ${cronString}`);
                const job = cron.schedule(cronString, () => {
                    runDataCollection(row.server);
                }, {
                    scheduled: true,
                    timezone: 'Europe/Berlin'
                });
                cronJobs[row.server] = job;
            }
        });
    } catch (error) {
        console.error('Fehler beim Starten des Schedulers:', error);
    }
}

function restartScheduler() {
    startScheduler();
}

const runSSH = (ip, command, useSudo = false) => {
    const cleanCommand = command.replace(/\s/g, ' ').trim();
    const escapedCommand = cleanCommand
    .replace(/"/g, '\\"')
    .replace(/`/g, '\\`')
    .replace(/\$/g, '\\$');

    const fullCommand = `ssh ${sshuser}@${ip} "${useSudo ? 'sudo ' : ''}${escapedCommand}"`;

    console.log(`[SSH-DEBUG] Führe aus: ${fullCommand}`);

    return new Promise((resolve, reject) => {
        exec(fullCommand, { timeout: 10000 }, (error, stdout, stderr) => {
            if (error) {
                const exitCode = error.code !== undefined ? `Exit Code: ${error.code}` : '';
                const signal = error.signal ? `Signal: ${error.signal}` : '';
                const errorMessage = `SSH Fehler für [${cleanCommand}]. Stderr: ${stderr.trim()}. Stdout: ${stdout.trim()}. Error: ${error.message} (${exitCode} ${signal})`;
                console.error(`[SSH-FEHLER] ${errorMessage}`);
                return reject(new Error(errorMessage));
            }
            resolve(stdout.trim());
        });
    });
};

async function collectDataViaSSH(ip) {
    const data = {
        server: ip,
        sys: 'N/A',
        pu: 0,
        ul: '',
        root_free: 'N/A'
    };

    try {
        // Explicit connectivity check: if this fails, throw so callers won't call insertOrUpdateData
        // (prevents updating last_run when the host is offline)
        await runSSH(ip, 'echo OK');

        await runSSH(ip, 'apt update', true).catch(e => console.log(`[WARN] apt update auf ${ip} fehlgeschlagen: ${e.message}`));
        data.sys = await runSSH(ip, 'lsb_release -ds').catch(() => 'Unbekanntes System');
        data.root_free = await runSSH(ip, "df -h / | tail -n 1 | awk '{print $4}'").catch(() => 'N/A');
        const updateOutputRaw = await runSSH(ip, 'apt list --upgradable', true).catch(() => '');

        let updateList = [];
        if (updateOutputRaw) {
            const lines = updateOutputRaw.split('\n');
            updateList = lines.filter(line => {
                const trimmed = line.trim();
                if (trimmed.length === 0) return false;
                if (trimmed.startsWith('Listing') || trimmed.startsWith('Auflistung')) return false;
                return true;
            });
        }
        data.ul = updateList.join('\n');
        data.pu = updateList.length;
        data.server = ip;
        return data;
    } catch (error) {
        // Re-throw so the caller can decide not to update last_run
        throw error;
    }
}

async function insertOrUpdateData(data) {
    const { server, sys, pu, ul, root_free } = data;
    const current_datetime = new Date().toISOString();

    const query = `
    INSERT INTO zustand (server, sys, pu, ul, root_free, last_run, is_offline)
    VALUES ($1, $2, $3, $4, $5, $6, false)
    ON CONFLICT (server)
    DO UPDATE SET
    sys=$2,
    pu=$3,
    ul=$4,
    root_free=$5,
    last_run=$6,
    is_offline=false;
    `;
    console.log(current_datetime);
    await pool.query(query, [server, sys, pu, ul, root_free, current_datetime]);
}

function sanitizeData(obj) {
    if (typeof obj !== 'object' || obj === null) {
        return obj;
    }
    for (const key in obj) {
        if (!obj.hasOwnProperty(key)) {
            continue;
        }
        const value = obj[key];
        if (typeof value === 'string') {
            obj[key] = value.replace(/[\u00A0\uFEFF]/g, ' ').trim();
        } else if (typeof value === 'object' && value !== null) {
            obj[key] = sanitizeData(value);
        }
    }
    return obj;
}




/**
 * Vergleicht zwei Debian-Versionsnummern.
 */
function compareVersions(v1, op, v2) {
    return new Promise((resolve, reject) => {
        const cleanV1 = v1.replace(/'/g, '').trim();
        const cleanV2 = v2.replace(/'/g, '').trim();
        const cleanOp = op.trim();

        const command = `dpkg --compare-versions '${cleanV1}' ${cleanOp} '${cleanV2}'`;

        exec(command, { timeout: 1000 }, (error, stdout, stderr) => {
            if (error) {
                if (error.code === 1 || error.code === 2) {
                    return resolve(false);
                }
                console.error(`[COMPARE-ERROR] dpkg-Vergleich fehlgeschlagen (${cleanV1} ${cleanOp} ${cleanV2}):`, stderr);
                return reject(new Error(`Versionsvergleich fehlgeschlagen: ${error.message}`));
            }
            resolve(true);
        });
    });
}


/**
 * Vergleicht zwei Debian-Versionsnummern.
 * Gibt 1 zurück, wenn v1 > v2; -1, wenn v1 < v2; 0, wenn v1 == v2.
 * Nutzt die Shell, um 'dpkg --compare-versions' zu nutzen, da Node.js keine native
 * dpkg-Versionslogik hat und diese sehr komplex ist.
 */
async function getVulnerableUpdates(ip, distroName, updatesListRaw) {
    if (!updatesListRaw || updatesListRaw.length === 0) {
        return [];
    }

    console.log(`[VULN-CHECK] Raw Updates für ${ip}:`, updatesListRaw.substring(0, 200));

    // 1. Installierte Pakete und Versionen parsen
    const installedPackages = updatesListRaw.split('\n')
    .map(line => line.trim())
    .filter(line => line.length > 0 && !line.startsWith('Listing') && !line.startsWith('Auflistung'))
    .map(line => {
        console.log(`[PARSE] Verarbeite Zeile: "${line}"`);

        // DEUTSCHE Version: "aktualisierbar von:"
        let match = line.match(/^([^\/]+)\/([^\s]+)\s+([^\s]+)\s+([^\s]+)\s+\[aktualisierbar von:\s+([^\]]+)\]/);

        // Falls nicht gefunden, versuche ENGLISCHE Version: "upgradable from:"
        if (!match) {
            match = line.match(/^([^\/]+)\/([^\s]+)\s+([^\s]+)\s+([^\s]+)\s+\[upgradable from:\s+([^\]]+)\]/);
        }

        if (match) {
            const packageName = match[1];
            const installedVersion = match[5].trim();

            console.log(`[MATCH-SUCCESS] Paket: ${packageName}, Installiert: ${installedVersion}`);

            return {
                packageName,
                installedVersion,
                currentDistro: match[2]
            };
        }

        // Fallback: Versuche einfacheres Pattern
        // Beispiel: "bind9/bullseye 1:9.16.50-1~deb11u1 amd64 [aktualisierbar von: 1:9.16.48-1]"
        const simplifiedMatch = line.match(/^([^\/\s]+).*\[(?:aktualisierbar|upgradable) (?:von|from):\s+([^\]]+)\]/);

        if (simplifiedMatch) {
            const packageName = simplifiedMatch[1];
            const installedVersion = simplifiedMatch[2].trim();

            console.log(`[FALLBACK-SUCCESS] Paket: ${packageName}, Installiert: ${installedVersion}`);

            return {
                packageName,
                installedVersion,
                currentDistro: distroName
            };
        }

        console.log(`[PARSE-FAILED] Konnte Zeile nicht parsen: "${line}"`);
        return null;
    })
    .filter(p => p && p.installedVersion);

    console.log(`[VULN-CHECK] Gefundene Pakete: ${installedPackages.length}`);
    console.log(`[VULN-CHECK] Pakete:`, installedPackages);

    if (installedPackages.length === 0) {
        console.log('[VULN-CHECK] Keine Pakete gefunden - beende Analyse');
        return [];
    }

    // 2. Datenbank-Abfrage nach CVEs für ALLE gefundenen Pakete
    const packageNames = installedPackages.map(p => p.packageName);

    console.log(`[VULN-CHECK] Suche CVEs für ${packageNames.length} Pakete in Distro: ${distroName}`);

    // WICHTIG: Die Spaltenreihenfolge in deiner DB ist:
    // cve_id, package_name, distro_name, vulnerable_version, fixed_version, current_status, priority_level, priority_color, description
    const query = `
    SELECT cve_id, package_name, fixed_version, priority_level, priority_color, current_status, description
    FROM debian_cve
    WHERE package_name = ANY($1)
    AND (distro_name = $2 OR distro_name = 'all')
    ORDER BY
    CASE priority_level
    WHEN 'high' THEN 1
    WHEN 'medium' THEN 2
    ELSE 3
    END, cve_id;
    `;

    console.log('[DB-QUERY] Parameters:', { packageNames, distroName });

    const cveResult = await pool.query(query, [packageNames, distroName]);
    const relevantCves = cveResult.rows;

    console.log(`[VULN-CHECK] Gefundene CVEs in DB: ${relevantCves.length}`);

    if (relevantCves.length > 0) {
        console.log('[DB-RESULT] Erste 3 CVEs:', relevantCves.slice(0, 3).map(c => ({
            cve: c.cve_id,
            pkg: c.package_name,
            fixed: c.fixed_version,
            status: c.current_status
        })));
    } else {
        console.log('[DB-RESULT] Keine CVEs gefunden. Teste manuell in der DB:');
        console.log(`  SELECT DISTINCT distro_name FROM debian_cve WHERE package_name = ANY(ARRAY['${packageNames.slice(0, 3).join("','")}']);`);
        console.log(`  SELECT COUNT(*) FROM debian_cve WHERE distro_name = '${distroName}' OR distro_name = 'all';`);
    }

    const vulnerableList = [];

    // 3. Iteriere über CVEs und wende die Versionsvergleichslogik an
    for (const cve of relevantCves) {
        const installedPackage = installedPackages.find(p => p.packageName === cve.package_name);

        if (!installedPackage) {
            console.log(`[SKIP] Kein installiertes Paket gefunden für CVE ${cve.cve_id} (${cve.package_name})`);
            continue;
        }

        const installedVer = installedPackage.installedVersion;
        const fixedVer = cve.fixed_version;
        const status = cve.current_status;

        console.log(`[CVE-CHECK] ${cve.cve_id} - ${cve.package_name}: Installiert=${installedVer}, Fix=${fixedVer}, Status=${status}`);

        // Regel 1: Wenn der Status 'open' ist, ist das System verwundbar
        if (status === 'open') {
            console.log(`[VULNERABLE] ${cve.package_name} - Status ist 'open'`);
            vulnerableList.push({
                ...cve,
                installed_version: installedVer,
                vulnerable_reason: "Fix ist noch nicht verfügbar (Status: open)."
            });
            continue;
        }

        // Regel 2: Skip resolved/not-affected wenn keine Fixed Version gesetzt
        if (!fixedVer || fixedVer === 'NULL' || fixedVer === '') {
            console.log(`[SKIP] ${cve.cve_id} - Keine fixed_version gesetzt, Status: ${status}`);
            continue;
        }

        // Regel 3: Versionsvergleich
        try {
            const isVulnerable = await compareVersions(installedVer, 'lt', fixedVer);

            console.log(`[VERSION-CHECK] ${cve.cve_id}: dpkg sagt: "${installedVer}" < "${fixedVer}" = ${isVulnerable}, Status=${status}`);

            // WICHTIG: Bei offensichtlich falschen Vergleichen (z.B. 140 < 45) einen Plausibilitäts-Check
            if (isVulnerable) {
                // Extrahiere die Major Version Numbers
                const installedMatch = installedVer.match(/^(\d+)/);
                const fixedMatch = fixedVer.match(/^(\d+)/);

                if (installedMatch && fixedMatch) {
                    const installedMajor = parseInt(installedMatch[1]);
                    const fixedMajor = parseInt(fixedMatch[1]);

                    console.log(`[VERSION-PLAUSIBILITY] Major Versions: Installiert=${installedMajor}, Fix=${fixedMajor}`);

                    // Wenn installierte Major Version deutlich HÖHER ist, ist dpkg wahrscheinlich verwirrt
                    if (installedMajor > fixedMajor * 2) {
                        console.log(`[FALSE-POSITIVE] ${cve.cve_id} - dpkg-Vergleich ergibt FALSE POSITIVE. Installiert (${installedMajor}) >> Fix (${fixedMajor})`);
                        console.log(`[WARNING] Bitte prüfen Sie die fixed_version in der Datenbank für ${cve.cve_id}!`);
                        continue; // Skip diesen CVE
                    }
                }
            }

            if (isVulnerable && status !== 'not-affected') {
                console.log(`[VULNERABLE] ${cve.package_name} - ${cve.cve_id} - Version zu alt`);
                vulnerableList.push({
                    ...cve,
                    installed_version: installedVer,
                    vulnerable_reason: `Installierte Version (${installedVer}) ist älter als Fix-Version (${fixedVer}).`
                });
            } else {
                console.log(`[SAFE] ${cve.cve_id} - Installierte Version ist aktuell genug oder not-affected`);
            }
        } catch (error) {
            console.error(`[ERROR] Versionsvergleich für ${cve.package_name} ${cve.cve_id}:`, error.message);
            // Bei Fehler im Versionsvergleich: Nur als verwundbar markieren wenn Status 'open' ist
            if (status === 'open') {
                vulnerableList.push({
                    ...cve,
                    installed_version: installedVer,
                    vulnerable_reason: `Fehler beim Versionsvergleich. Status: ${status}. (${error.message.substring(0, 50)}...)`
                });
            }
        }
    }

    console.log(`[VULN-CHECK] Fertig - ${vulnerableList.length} Schwachstellen gefunden`);
    return vulnerableList;
}



async function runDataCollection(ip) {
    console.log(`[CRON] Starte Datensammlung für ${ip}`);
    try {
        const data = await collectDataViaSSH(ip);
        const sanitizedData = sanitizeData(data);
        await insertOrUpdateData(sanitizedData);
        console.log(`[CRON] Datensammlung für ${ip} erfolgreich.`);
    } catch (error) {
        console.error(`[CRON] FEHLER bei Datensammlung für ${ip}: ${error.message}`);
        // Setze is_offline auf true wenn Datensammeln fehlschlägt
        await pool.query('UPDATE zustand SET is_offline = true WHERE server = $1', [ip]);
    }
}

function checkIpInLogFile(ip) {
    try {
        const logData = fs.readFileSync('idlist.log', 'utf8');
        const logEntries = logData.split('\n').map(entry => entry.trim()).filter(line => line.length > 0);
        return logEntries.includes(ip);
    } catch (error) {
        return false;
    }
}

// --- AKTIONEN MIT PROGRESS (WEBSOCKETS) ---

function execSelectedUpdateWithProgress(ip, packages) {
    const packageList = packages.join(' ');
    const installCommand = `ssh ${sshuser}@${ip} 'sudo apt install -y ${packageList}'`;

    // ... (WebSocket-Logik bleibt gleich)
    wss.clients.forEach(client => {
        if (client.readyState === WebSocket.OPEN) {
            client.send(`Starte gezieltes Update auf ${ip} für Pakete: ${packageList.substring(0, 100)}...`);
        }
    });

    const process1 = exec(installCommand);

    process1.stdout.on('data', (data) => {
        wss.clients.forEach(client => { if (client.readyState === WebSocket.OPEN) client.send(`sudo apt install: ${data.toString()}`); });
    });

    process1.stderr.on('data', (data) => {
        wss.clients.forEach(client => { if (client.readyState === WebSocket.OPEN) client.send(`Fehler bei apt install: ${data.toString()}`); });
    });

    // NEUE LOGIK: Nach Abschluss der Installation
    process1.on('close', async (code) => {
        if (code === 0) {
            wss.clients.forEach(client => { if (client.readyState === WebSocket.OPEN) client.send(`[SYSTEM] apt install abgeschlossen mit Code ${code}. Starte Aktualisierung des Systemzustands...`); });

            try {
                // Führe die Datensammlung asynchron aus
                await runDataCollection(ip);
                wss.clients.forEach(client => { if (client.readyState === WebSocket.OPEN) client.send(`[FINISH] Systemzustand erfolgreich neu erfasst. Tabelle kann aktualisiert werden.`); });
            } catch (e) {
                console.error(`Fehler bei erneuter Datensammlung für ${ip}:`, e);
                wss.clients.forEach(client => { if (client.readyState === WebSocket.OPEN) client.send(`[FEHLER] Datensammlung nach Update fehlgeschlagen: ${e.message}`); });
            }
        } else {
            // Fehlerfall
            wss.clients.forEach(client => { if (client.readyState === WebSocket.OPEN) client.send(`[FEHLER] apt install fehlgeschlagen mit Exit Code: ${code}.`); });
        }
    });
}


function execUpdateWithProgress(ip) {
    const upgradeCommand = `ssh ${sshuser}@${ip} 'sudo apt upgrade -y'`;

    const process1 = exec(upgradeCommand);

    process1.stdout.on('data', (data) => {
        wss.clients.forEach(client => { if (client.readyState === WebSocket.OPEN) client.send(`sudo apt upgrade: ${data.toString()}`); });
    });

    process1.stderr.on('data', (data) => {
        wss.clients.forEach(client => { if (client.readyState === WebSocket.OPEN) client.send(`Fehler bei apt upgrade: ${data.toString()}`); });
    });

    // NEUE LOGIK: Nach Abschluss des Upgrades
    process1.on('close', async (code) => {
        if (code === 0) {
            wss.clients.forEach(client => { if (client.readyState === WebSocket.OPEN) client.send(`[SYSTEM] apt upgrade abgeschlossen mit Code ${code}. Starte Aktualisierung des Systemzustands...`); });

            try {
                // Führe die Datensammlung asynchron aus
                await runDataCollection(ip);
                wss.clients.forEach(client => { if (client.readyState === WebSocket.OPEN) client.send(`[FINISH] Systemzustand erfolgreich neu erfasst. Tabelle kann aktualisiert werden.`); });
            } catch (e) {
                console.error(`Fehler bei erneuter Datensammlung für ${ip}:`, e);
                wss.clients.forEach(client => { if (client.readyState === WebSocket.OPEN) client.send(`[FEHLER] Datensammlung nach Upgrade fehlgeschlagen: ${e.message}`); });
            }
        } else {
            // Fehlerfall
            wss.clients.forEach(client => { if (client.readyState === WebSocket.OPEN) client.send(`[FEHLER] apt upgrade fehlgeschlagen mit Exit Code: ${code}.`); });
        }
    });
}

function unlockAptOnRemoteServer(ip) {
    console.log(`[UNLOCK-APT] Starte apt-Entsperrung auf ${ip}...`);
    
    // Ausführung der beiden Befehle nacheinander
    const killAptCommand = `ssh ${sshuser}@${ip} 'sudo pkill apt'`;
    const configureCommand = `ssh ${sshuser}@${ip} 'sudo dpkg --configure -a'`;

    // 1. Schritt: pkill apt
    exec(killAptCommand, (error, stdout, stderr) => {
        if (error) {
            console.error(`[UNLOCK-APT] Fehler bei pkill apt auf ${ip}:`, error.message);
            wss.clients.forEach(client => { if (client.readyState === WebSocket.OPEN) client.send(`[UNLOCK-APT] Fehler bei pkill apt: ${stderr || error.message}\n`); });
        } else {
            console.log(`[UNLOCK-APT] pkill apt erfolgreich auf ${ip}`);
            wss.clients.forEach(client => { if (client.readyState === WebSocket.OPEN) client.send(`[UNLOCK-APT] ✓ sudo pkill apt erfolgreich ausgeführt\n`); });
            
            // 2. Schritt: dpkg --configure -a
            exec(configureCommand, (error, stdout, stderr) => {
                if (error) {
                    console.error(`[UNLOCK-APT] Fehler bei dpkg --configure -a auf ${ip}:`, error.message);
                    wss.clients.forEach(client => { if (client.readyState === WebSocket.OPEN) client.send(`[UNLOCK-APT] Fehler bei dpkg --configure -a: ${stderr || error.message}\n`); });
                } else {
                    console.log(`[UNLOCK-APT] dpkg --configure -a erfolgreich auf ${ip}`);
                    wss.clients.forEach(client => { if (client.readyState === WebSocket.OPEN) client.send(`[UNLOCK-APT] ✓ sudo dpkg --configure -a erfolgreich ausgeführt\n`); });
                }
                wss.clients.forEach(client => { if (client.readyState === WebSocket.OPEN) client.send(`[UNLOCK-APT] Prozess abgeschlossen.\n`); });
            });
        }
    });
}


// ----------------------------------------------------------------------
// --- ENDPUNKTE (ROUTING) ---
// ----------------------------------------------------------------------

// --- ÖFFENTLICHE ENDPUNKTE (Kein requireLogin, da von Middleware ausgeschlossen) ---

app.get('/api/bootstrap/grund.sh', (req, res) => {
    const scriptPath = path.join(__dirname, 'public', 'grund.sh');
    res.setHeader('Content-Type', 'text/x-shellscript');
    fs.createReadStream(scriptPath)
    .on('error', (err) => {
        console.error('Fehler beim Ausliefern von grund.sh:', err);
        res.status(404).send('# Fehler: Skript nicht gefunden');
    })
    .pipe(res);
});

app.get('/api/config', (req, res) => {
    const serverUrl = `${req.protocol}://${req.get('host')}`;
    const bootstrapUrl = `${serverUrl}/api/bootstrap/grund.sh`;
    const curlCommand = `curl -sS ${bootstrapUrl} | sudo bash`;
    res.json({
        curlCommand: curlCommand
    });
});

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body; // Jetzt funktioniert req.body!

    try {
        const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Benutzername oder Passwort falsch.' });
        }
        const user = result.rows[0];
        const passwordMatch = await bcrypt.compare(password, user.password_hash);
        if (!passwordMatch) {
            return res.status(401).json({ error: 'Benutzername oder Passwort falsch.' });
        }

        // Bei erfolgreichem Login: Session-Daten setzen und Cookie im Browser speichern
        req.session.userId = user.id;
        req.session.username = user.username;
        req.session.isAdmin = user.is_admin;
        // Setze Cookies, die das Frontend für die Initialisierung nutzen kann
        res.cookie('username', user.username, { maxAge: 24 * 60 * 60 * 1000, httpOnly: false });
        res.cookie('isAdmin', user.is_admin, { maxAge: 24 * 60 * 60 * 1000, httpOnly: false });

        res.json({ success: true, username: user.username, isAdmin: user.is_admin });

    } catch (error) {
        console.error('Login-Fehler:', error);
        res.status(500).json({ error: 'Interner Serverfehler.' });
    }
});


app.get('/api/status', (req, res) => {
    // Wenn Login deaktiviert ist: Immer true zurückgeben
    if (!ENABLE_LOGIN) {
        return res.json({
            loggedIn: true,
            username: DEFAULT_USERNAME,
            isAdmin: false
        });
    }

    // Wenn Login aktiviert ist: Session-Daten prüfen
    res.json({
        loggedIn: true,
        username: req.session.username,
        isAdmin: req.session.isAdmin
    });
});

// --- GESCHÜTZTE ENDPUNKTE (requireLogin greift hier) ---

app.post('/api/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.status(500).json({ error: 'Logout fehlgeschlagen.' });
        }
        res.clearCookie('connect.sid');
        res.clearCookie('username');
        res.clearCookie('isAdmin');
        res.json({ success: true });
    });
});


app.get('/api/vulnerableUpdates/:id', async (req, res) => {
    const { id } = req.params;

    try {
        // 1. Hole Server-Details und Update-Liste
        const serverQuery = await pool.query('SELECT server, sys, ul FROM zustand WHERE id = $1', [id]);

        if (serverQuery.rows.length === 0) {
            return res.status(404).json({ error: 'Server nicht gefunden.' });
        }

        const { server, sys, ul } = serverQuery.rows[0];

        // Extrahieren des Debian-Codenamen aus dem 'sys'-Feld (z.B. 'Debian GNU/Linux 11 (bullseye)')
        const matchDistro = sys.match(/\(([^)]+)\)/);
const distroName = matchDistro ? matchDistro[1].toLowerCase() : null;

if (!distroName) {
    return res.status(400).json({ error: 'Distributionsname konnte nicht extrahiert werden.' });
}

console.log(`[VULN-CHECK] Starte Analyse für ${server} (Distro: ${distroName})`);

// 2. Führe die Versionsvergleichslogik durch
const vulnerableList = await getVulnerableUpdates(server, distroName, ul);

// 3. Ausgabe
res.json({
    success: true,
    distroName: distroName,
    vulnerabilities: vulnerableList
});

    } catch (error) {
        console.error('Fehler beim Abrufen der verwundbaren Updates:', error);
        res.status(500).json({ error: 'Interner Serverfehler beim Versionsvergleich.' });
    }
});

app.post('/api/changePassword', async (req, res) => {
    const { oldPassword, newPassword } = req.body;
    const userId = req.session.userId;

    if (!userId) {
        return res.status(401).json({ error: 'Nicht authentifiziert.' });
    }

    try {
        const result = await pool.query('SELECT password_hash FROM users WHERE id = $1', [userId]);
        const user = result.rows[0];

        const passwordMatch = await bcrypt.compare(oldPassword, user.password_hash);
        if (!passwordMatch) {
            return res.status(401).json({ error: 'Altes Passwort falsch.' });
        }

        const newPasswordHash = await bcrypt.hash(newPassword, saltRounds);
        await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [newPasswordHash, userId]);

        res.json({ success: true, message: 'Passwort erfolgreich geändert.' });

    } catch (error) {
        console.error('Passwortänderungsfehler:', error);
        res.status(500).json({ error: 'Interner Serverfehler.' });
    }
});


// --- ADMIN ENDPUNKTE ---

app.post('/api/admin/addUser', requireAdmin, async (req, res) => {
    const { username, password, isAdmin } = req.body;
    try {
        const passwordHash = await bcrypt.hash(password, saltRounds);
        await pool.query(
            'INSERT INTO users (username, password_hash, is_admin) VALUES ($1, $2, $3)',
                         [username, passwordHash, isAdmin || false]
        );
        res.json({ success: true, message: `Benutzer ${username} erfolgreich erstellt.` });
    } catch (error) {
        if (error.code === '23505') {
            return res.status(409).json({ error: 'Benutzername existiert bereits.' });
        }
        console.error('Benutzer-Hinzufügen-Fehler:', error);
        res.status(500).json({ error: 'Fehler beim Hinzufügen des Benutzers.' });
    }
});

app.post('/api/admin/resetPassword', requireAdmin, async (req, res) => {
    const { userId, newPassword } = req.body;
    try {
        const passwordHash = await bcrypt.hash(newPassword, saltRounds);
        await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [passwordHash, userId]);
        res.json({ success: true, message: `Passwort für Benutzer ${userId} erfolgreich zurückgesetzt.` });
    } catch (error) {
        console.error('Passwort-Reset-Fehler:', error);
        res.status(500).json({ error: 'Fehler beim Zurücksetzen des Passworts.' });
    }
});

app.get('/api/admin/users', requireAdmin, async (req, res) => {
    try {
        const result = await pool.query('SELECT id, username, is_admin FROM users ORDER BY id');
        res.json(result.rows);
    } catch (error) {
        console.error('Benutzerliste-Fehler:', error);
        res.status(500).json({ error: 'Fehler beim Abrufen der Benutzerliste.' });
    }
});

// --- SERVER-MANAGEMENT ENDPUNKTE ---

app.post('/api/addServer', async (req, res) => {
    const { ip } = req.body;
    try {
        const query = `
        INSERT INTO zustand (server, sys, pu, ul, root_free, last_run, schedule_type, schedule_time, is_offline)
        VALUES ($1, 'N/A', 0, '', 'N/A', NOW(), 'hourly', NULL, false)
        ON CONFLICT (server) DO NOTHING
        RETURNING id;
        `;
        const result = await pool.query(query, [ip]);

        if (result.rowCount === 0) {
            return res.status(409).json({ error: 'Server existiert bereits.' });
        }
        
        // Starte den Scheduler neu, damit der neue Server sofort eingeplant wird
        restartScheduler();
        
        res.json({ success: true, id: result.rows[0].id });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Fehler beim Hinzufügen des Servers.' });
    }
});

app.post('/api/schedule', async (req, res) => {
    const { id, type, time, day } = req.body;
    try {
        // Füge schedule_day Spalte hinzu, falls noch nicht vorhanden
        await pool.query(`
            ALTER TABLE zustand
            ADD COLUMN IF NOT EXISTS schedule_day text DEFAULT '0'
        `);
        
        // Speichere schedule_type, schedule_time und optional schedule_day
        if (type === 'weekly' && day !== undefined) {
            await pool.query(
                'UPDATE zustand SET schedule_type = $1, schedule_time = $2, schedule_day = $3 WHERE id = $4',
                [type, time, day, id]
            );
        } else {
            await pool.query(
                'UPDATE zustand SET schedule_type = $1, schedule_time = $2, schedule_day = NULL WHERE id = $3',
                [type, time, id]
            );
        }
        
        restartScheduler();
        res.json({ success: true });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Fehler beim Speichern des Zeitplans.' });
    }
});

app.delete('/api/deleteServer', async (req, res) => {
    const { id } = req.body;
    try {
        const result = await pool.query('SELECT server FROM zustand WHERE id = $1', [id]);
        if (result.rows.length > 0 && cronJobs[result.rows[0].server]) {
            cronJobs[result.rows[0].server].stop();
            delete cronJobs[result.rows[0].server];
        }

        await pool.query('DELETE FROM zustand WHERE id = $1', [id]);
        res.json({ success: true });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Fehler beim Löschen des Servers.' });
    }
});

// index.js (Ersetzt den Endpunkt app.get('/api/zustand', ...))

// index.js (Ersetzt den Endpunkt app.get('/api/zustand', ...))

app.get('/api/zustand', async (req, res) => {
    try {
        const result = await pool.query(`
        SELECT
        server, sys, pu, ul, root_free, zus, komment, schedule_type, schedule_time, id, is_offline,
        to_char(last_run AT TIME ZONE '${GLOBAL_TIMEZONE}', '${GLOBAL_DATE_FORMAT}') AS last_run_local
        FROM zustand
        ORDER BY
        CAST(SPLIT_PART(server, '.', 4) AS INTEGER)
        `);
        const zustandList = result.rows.map(row => {
            return {
                ...row,
                inLogFile: checkIpInLogFile(row.server),
                last_run: row.last_run_local
                    };
            });


        res.json(zustandList);
        } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Fehler beim Abrufen der Daten.' });

    }

});




app.get('/api/users', requireAdmin, async (req, res) => {
    try {
        // ANPASSUNG: PostgreSQL Syntax (pool.query)
        const result = await pool.query('SELECT id, username, is_admin FROM users ORDER BY id');
        // PostgreSQL liefert Daten in result.rows
        res.json(result.rows);
    } catch (error) {
        console.error('Fehler beim Abrufen der Benutzer:', error);
        res.status(500).json({ success: false, message: 'Interner Serverfehler.' });
    }
});


app.post('/api/createUser', requireAdmin, async (req, res) => {
    const { username, password, isAdmin } = req.body;

    if (!username || !password || password.length < 6) {
        return res.status(400).json({ success: false, message: 'Ungültige Eingabe.' });
    }

    try {
        // 1. Prüfen, ob der Benutzername bereits existiert
        // ANPASSUNG: PostgreSQL Syntax und pool.query
        const existingUserResult = await pool.query('SELECT id FROM users WHERE username = $1', [username]);
        if (existingUserResult.rows.length > 0) { // PostgreSQL prüft rows.length
            return res.status(409).json({ success: false, message: 'Benutzername existiert bereits.' });
        }

        const passwordHash = await bcrypt.hash(password, saltRounds); // Verwende saltRounds
        const isAdminValue = isAdmin ? true : false; // PostgreSQL verwendet TRUE/FALSE für Boolean

        // 2. Benutzer einfügen
        // ANPASSUNG: PostgreSQL Syntax, Feldname password_hash, $1, $2, $3
        await pool.query(
            'INSERT INTO users (username, password_hash, is_admin) VALUES ($1, $2, $3)',
                         [username, passwordHash, isAdminValue]
        );

        res.json({ success: true, message: 'Benutzer erfolgreich erstellt.' });
    } catch (error) {
        // PostgreSQL Eindeutigkeitsverletzung (Unique Constraint) hat Code '23505'
        if (error.code === '23505') {
            return res.status(409).json({ success: false, message: 'Benutzername existiert bereits.' });
        }
        console.error('Fehler beim Erstellen des Benutzers:', error);
        res.status(500).json({ success: false, message: 'Interner Serverfehler.' });
    }
});

app.delete('/api/deleteUser', requireAdmin, async (req, res) => {
    const { id } = req.body;
    const currentUserId = req.session.userId;

    if (!id || isNaN(id)) {
        return res.status(400).json({ success: false, message: 'Ungültige Benutzer-ID.' });
    }

    if (Number(id) === currentUserId) {
        return res.status(403).json({ success: false, message: 'Sie können Ihr eigenes Konto nicht löschen.' });
    }

    try {
        // ANPASSUNG: PostgreSQL Syntax (pool.query)
        const result = await pool.query('DELETE FROM users WHERE id = $1', [id]);

        if (result.rowCount === 0) { // PostgreSQL prüft rowCount
            return res.status(404).json({ success: false, message: 'Benutzer nicht gefunden.' });
        }

        res.json({ success: true, message: 'Benutzer erfolgreich gelöscht.' });
    } catch (error) {
        console.error('Fehler beim Löschen des Benutzers:', error);
        res.status(500).json({ success: false, message: 'Interner Serverfehler.' });
    }
});



app.get('/api/serverupdates/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const result = await pool.query('SELECT ul FROM zustand WHERE id = $1', [id]);
        if (result.rows.length > 0) {
            const updates = result.rows[0].ul || '';
            const updateList = updates
            .split('\n')
            .map(line => line.trim())
            .filter(line => line.length > 0);
            res.json(updateList);
        } else {
            res.status(404).json({ error: 'Server nicht gefunden.' });
        }
    } catch (error) {
        console.error('Fehler beim Abrufen der Updates:', error);
        res.status(500).json({ error: 'Fehler beim Abrufen der Updates.' });
    }
});

app.post('/api/update', async (req, res) => {
    const { id, field, value } = req.body;
    try {
        await pool.query(`UPDATE zustand SET ${field} = $1 WHERE id = $2`, [value, id]);
        res.json({ success: true });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Fehler beim Aktualisieren der Daten.' });
    }
});

app.post('/api/action', async (req, res) => {
    const { ip, action, packages } = req.body;

    if (action === 'connectSSH') {
        let success = false;
        const copyKeyCommand = `sshpass -p "${sshpass}" ssh-copy-id -o "StrictHostKeyChecking=accept-new" -i /root/.ssh/id_rsa.pub ${sshuser}@${ip}`;

        console.log(`[SSH-KEY] Versuche, Schlüssel nach ${ip} zu kopieren...`);

        try {
            await new Promise((resolve, reject) => {
                exec(copyKeyCommand, { timeout: 30000 }, (error, stdout, stderr) => {
                    if (error) {
                        console.error(`[SSH-KEY-FEHLER] Schlüsselkopie fehlgeschlagen für ${ip}. Stderr: ${stderr.trim()}. Error: ${error.message}`);
                        return reject(error);
                    }
                    console.log(`[SSH-KEY] Schlüssel erfolgreich kopiert.`);
                    resolve();
                });
            });

            const newRandomPassword = crypto.randomBytes(24).toString('base64').slice(0, 32);
            const changePassCommand = `${sshuser}:${newRandomPassword}`.replace(/"/g, '\\"');

            await runSSH(ip, `echo "${changePassCommand}" | sudo chpasswd`, true);

            console.log(`[SECURITY] Passwort für ${sshuser}@${ip} erfolgreich auf zufälligen Wert geändert.`);

            const data = await collectDataViaSSH(ip);
            const sanitizedData = typeof sanitizeData === 'function' ? sanitizeData(data) : data;
            await insertOrUpdateData(sanitizedData);

            fs.appendFileSync('idlist.log', `\n${ip}`);

            success = true;

        } catch (error) {
            console.error(`Fehler bei connectSSH (Schlüsselkopie oder Datensammlung) auf ${ip}: ${error.message}`);
            try {
                const logData = fs.readFileSync('idlist.log', 'utf8').split('\n').filter(line => line.trim() !== ip).join('\n');
                fs.writeFileSync('idlist.log', logData);
            } catch (e) {
                console.error("Fehler beim Löschen aus idlist.log:", e);
            }
            return res.status(500).json({ error: `Fehler beim Verbindungsaufbau via SSH und Datensammlung: ${error.message.substring(0, 100)}...` });
        }

        if (success) {
            return res.json({ success: true });
        }
    } else if (action === 'updateServer') {
        execUpdateWithProgress(ip);
        res.json({ success: true });
    } else if (action === 'updateSelected') {
        if (!packages || packages.length === 0) {
            return res.status(400).json({ error: 'Keine Pakete für das Update ausgewählt.' });
        }
        execSelectedUpdateWithProgress(ip, packages);
        res.json({ success: true });
    } else if (action === 'unlockApt') {
        unlockAptOnRemoteServer(ip);
        res.json({ success: true });
    } else {
        res.status(400).json({ error: 'Ungültige Aktion.' });
    }
});

// Manuelles Datensammeln für einen spezifischen Server
app.post('/api/collectData', async (req, res) => {
    const { ip, id } = req.body;

    if (!ip) {
        return res.status(400).json({ error: 'IP-Adresse erforderlich.' });
    }

    try {
        console.log(`[COLLECT] Starte manuelles Datensammeln für ${ip}...`);
        
        const data = await collectDataViaSSH(ip);
        const sanitizedData = typeof sanitizeData === 'function' ? sanitizeData(data) : data;
        await insertOrUpdateData(sanitizedData);

        console.log(`[COLLECT] Datensammeln erfolgreich für ${ip}`);
        res.json({ success: true, message: `Daten erfolgreich gesammelt von ${ip}` });
    } catch (error) {
        console.error(`[COLLECT] Fehler beim Datensammeln für ${ip}:`, error.message);
        // Setze is_offline auf true wenn Datensammeln fehlschlägt
        await pool.query('UPDATE zustand SET is_offline = true WHERE server = $1', [ip]);
        res.status(500).json({ error: `Fehler beim Datensammeln: ${error.message.substring(0, 100)}` });
    }
});

// --- INIT: SSH-Konfiguration lesen und Scheduler starten ---
fs.readFile(filePath, 'utf8', (err, data) => {
    initializeAdminUser();
    if (err) {
        return console.error('Fehler beim Lesen der SSH-Konfigurationsdatei:', err);
    }

    const lines = data.split('\n');

    lines.forEach(line => {
        if (line.startsWith('user:')) {
            sshuser = line.split(':')[1].replace(/"/g, '').trim();
        } else if (line.startsWith('password:')) {
            sshpass = line.split(':')[1].replace(/"/g, '').trim();
        }
    });

    startScheduler();
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});


// --- SERVER START ---
const server = app.listen(port, () => {
    console.log(`Patch-Management Server läuft auf http://localhost:${port}`);
});

// --- SSH2 REMOTE CONSOLE HANDLER ---

const sshSessions = new Map(); // Speichert aktive SSH-Sessions

function createSSHTerminal(socket, host, username, password) {
    console.log(`[SSH] Starte SSH-Session für ${username}@${host}`);
    
    // Nutze node-pty für echten PTY-Support
    const ptyProcess = spawnPty('sshpass', 
        [
            '-p', password,
            'ssh',
            '-o', 'StrictHostKeyChecking=no',
            '-o', 'UserKnownHostsFile=/dev/null',
            '-o', 'LogLevel=quiet',
            '-o', 'PasswordAuthentication=yes',
            '-o', 'PubkeyAuthentication=no',
            '-tt',
            `${username}@${host}`
        ],
        {
            name: 'xterm-256color',
            cols: 120,
            rows: 30,
            cwd: process.env.HOME,
            env: Object.assign({}, process.env, {
                TERM: 'xterm-256color',
                LANG: 'en_US.UTF-8'
            })
        }
    );

    const sessionId = `${host}-${Date.now()}`;
    sshSessions.set(socket, { 
        proc: ptyProcess, 
        sessionId
    });

    console.log(`[SSH] PTY-Prozess gestartet für ${sessionId}`);

    // Sende initialen Output
    socket.send(JSON.stringify({ 
        type: 'output', 
        data: `Verbunden zu ${username}@${host}\n`
    }));

    // Handle alle Daten vom PTY
    ptyProcess.onData((data) => {
        console.log(`[SSH-data] ${data.substring(0, 50)}`);
        
        if (socket && socket.readyState === WebSocket.OPEN) {
            socket.send(JSON.stringify({ 
                type: 'output', 
                data: data
            }));
        }
    });

    // Handle close
    ptyProcess.onExit((event) => {
        console.log(`[SSH] PTY-Prozess geschlossen für ${sessionId}`);
        
        if (socket && socket.readyState === WebSocket.OPEN) {
            socket.send(JSON.stringify({ 
                type: 'output', 
                data: `\n[Verbindung geschlossen]\n`
            }));
        }
        sshSessions.delete(socket);
    });

    // Handle Fehler (wenn sshpass nicht vorhanden)
    ptyProcess.on?.('error', (err) => {
        console.error(`[SSH] PTY-Fehler für ${sessionId}:`, err);
        
        if (socket && socket.readyState === WebSocket.OPEN) {
            socket.send(JSON.stringify({ 
                type: 'error', 
                data: `Fehler: ${err.message}`
            }));
        }
        sshSessions.delete(socket);
    });
}

// WebSocket-Handler
const wss = new WebSocket.Server({ noServer: true });

server.on('upgrade', (request, socket, head) => {
    const url = request.url;
    
    // SSH Remote Console WebSocket
    if (url.startsWith('/api/ssh-terminal/')) {
        const parts = url.split('/');
        const host = parts[3];
        const username = decodeURIComponent(parts[4]);
        
        wss.handleUpgrade(request, socket, head, (ws) => {
            // Der Password kommt über die erste WebSocket-Message
            let passwordReceived = false;
            
            ws.on('message', (message) => {
                try {
                    const msg = JSON.parse(message.toString());
                    
                    if (!passwordReceived && msg.type === 'auth') {
                        passwordReceived = true;
                        console.log(`[WS] Auth-Message für ${host}/${username}`);
                        createSSHTerminal(ws, host, username, msg.password);
                    } else if (passwordReceived && msg.type === 'input') {
                        const session = sshSessions.get(ws);
                        if (session && session.proc) {
                            // Input direkt in den PTY schreiben
                            console.log(`[WS] Input erhalten: ${msg.data.substring(0, 50)}...`);
                            session.proc.write(msg.data);
                        } else {
                            console.warn('[WS] Keine aktive Session für Input');
                        }
                    }
                } catch (e) {
                    console.error('[WS] Fehler beim Verarbeiten der Nachricht:', e);
                }
            });
            
            ws.on('close', () => {
                const session = sshSessions.get(ws);
                if (session && session.proc) {
                    session.proc.kill();
                    sshSessions.delete(ws);
                }
            });
        });
    } else {
        // Standard Patch-Management WebSocket (für Updates)
        wss.handleUpgrade(request, socket, head, socket => {
            wss.emit('connection', socket, request);
        });
    }
});

