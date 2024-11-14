// index.js
const express = require('express');
const { Pool } = require('pg');
const bodyParser = require('body-parser');
const fs = require('fs');
const { exec } = require('child_process');
const WebSocket = require('ws');
const path = require('path');

const app = express();
const port = 3000;

// PostgreSQL-Verbindung einrichten
const pool = new Pool({
    user: 'postgres',
    host: 'localhost',
    database: 'apt',
    password: 'postgres',
    port: 5432
});

    let sshuser = '';
    let sshpass = '';

// Pfad zur Datei ssh.conf
const filePath = path.join(__dirname, 'ssh.conf');

// Funktion zum Lesen und Verarbeiten der Datei
fs.readFile(filePath, 'utf8', (err, data) => {
    if (err) {
        return console.error('Fehler beim Lesen der Datei:', err);
    }
    
    // Zeilenweise aufteilen
    const lines = data.split('\n');
    
    // Durch die Zeilen gehen und die Werte extrahieren
    lines.forEach(line => {
        if (line.startsWith('user:')) {
            sshuser = line.split(':')[1].replace(/"/g, '').trim();
        } else if (line.startsWith('password:')) {
            sshpass = line.split(':')[1].replace(/"/g, '').trim();
        }
    });
    const sshuserx = sshuser;
    const sshpassx = sshpass;
    // Ausgabe der Variablen
    //console.log('sshuser:', sshuserx);
    //console.log('sshpass:', sshpass);
});


app.use(bodyParser.json());
app.use(express.static('public'));

app.delete('/api/deleteServer', async (req, res) => {
    const { id } = req.body;
    try {
        await pool.query('DELETE FROM zustand WHERE id = $1', [id]);
        res.json({ success: true });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Fehler beim Löschen des Servers.' });
    }
});

// WebSocket-Server initialisieren
const wss = new WebSocket.Server({ noServer: true });

// Hilfsfunktion zum Überprüfen, ob eine IP in der idlist.log-Datei vorhanden ist
function checkIpInLogFile(ip) {
    try {
        const logData = fs.readFileSync('idlist.log', 'utf8');
        const logEntries = logData.split('\n').map(entry => entry.trim());
        return logEntries.includes(ip);
    } catch (error) {
        console.error('Fehler beim Lesen der idlist.log-Datei:', error);
        return false;
    }
}

// Endpunkt zum Abrufen der Zustände, sortiert nach dem letzten Oktett der IP
app.get('/api/zustand', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT *
            FROM zustand
            ORDER BY
                CAST(SPLIT_PART(server, '.', 4) AS INTEGER)
        `);

        const zustandList = result.rows.map(row => {
            return {
                ...row,
                inLogFile: checkIpInLogFile(row.server)
            };
        });

        res.json(zustandList);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Fehler beim Abrufen der Daten.' });
    }
});

// Endpunkt zum Speichern eines Freitextes in der Spalte "zus" oder "komment"
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

// Endpunkt für Aktionen (connect SSH oder Update)
app.post('/api/action', (req, res) => {
    const { ip, action } = req.body;

    if (action === 'connectSSH') {
        // Schreibt die IP in eine temporäre Datei und führt ein Shell-Skript aus
        fs.writeFileSync('simp.tmp', ip);
        exec('./imp.sh', (error) => {
            if (error) {
                console.error(error);
                res.status(500).json({ error: 'Fehler beim Verbindungsaufbau via SSH.' });
            } else {
                res.json({ success: true });
            }
        });
    } else if (action === 'updateServer') {
        // Startet den Updateprozess und gibt den Fortschritt über WebSockets aus
        execUpdateWithProgress(ip);
        res.json({ success: true });
    } else {
        res.status(400).json({ error: 'Ungültige Aktion.' });
    }
});

// Funktion, die den Updateprozess ausführt und Statusmeldungen sendet
function execUpdateWithProgress(ip) {
    // Erstes Kommando: apt upgrade -y
    const upgradeCommand = `ssh ${sshuser}@${ip} 'apt upgrade -y'`;
    // Zweites Kommando: /local/patch.sh
    const patchCommand = `ssh ${sshuser}@${ip} '/local/patch.sh'`;

    // Erstes Kommando ausführen
    const process1 = exec(upgradeCommand);

    // Output von apt upgrade -y senden
    process1.stdout.on('data', (data) => {
        wss.clients.forEach(client => {
            if (client.readyState === WebSocket.OPEN) {
                client.send(`apt upgrade: ${data.toString()}`);
            }
        });
    });

    process1.stderr.on('data', (data) => {
        wss.clients.forEach(client => {
            if (client.readyState === WebSocket.OPEN) {
                client.send(`Fehler bei apt upgrade: ${data.toString()}`);
            }
        });
    });

    process1.on('close', (code) => {
        // Wenn das erste Kommando abgeschlossen ist, führe das zweite aus
        wss.clients.forEach(client => {
            if (client.readyState === WebSocket.OPEN) {
                client.send(`apt upgrade abgeschlossen mit Code: ${code}. Starte patch.sh...`);
            }
        });

        // Zweites Kommando ausführen
        const process2 = exec(patchCommand);

        // Output von /local/patch.sh senden
        process2.stdout.on('data', (data) => {
            wss.clients.forEach(client => {
                if (client.readyState === WebSocket.OPEN) {
                    client.send(`patch.sh: ${data.toString()}`);
                }
            });
        });

        process2.stderr.on('data', (data) => {
            wss.clients.forEach(client => {
                if (client.readyState === WebSocket.OPEN) {
                    client.send(`Fehler bei patch.sh: ${data.toString()}`);
                }
            });
        });

        process2.on('close', (code) => {
            // Wenn das zweite Kommando abgeschlossen ist, sende eine Abschlussmeldung
            wss.clients.forEach(client => {
                if (client.readyState === WebSocket.OPEN) {
                    client.send(`patch.sh abgeschlossen mit Code: ${code}`);
                }
            });
        });
    });
}

// WebSocket-Server konfigurieren, um HTTP-Upgrades zu verarbeiten
const server = app.listen(port, () => {
    console.log(`Server läuft unter http://localhost:${port}`);
});

server.on('upgrade', (request, socket, head) => {
    wss.handleUpgrade(request, socket, head, ws => {
        wss.emit('connection', ws, request);
    });
});
