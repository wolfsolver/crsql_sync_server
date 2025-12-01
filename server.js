// server.js
// Aggiungi all'inizio del file server.js:
const express = require('express');
const sqlite3 = require('sqlite3');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto'); // Per generare ID e chiavi
const TABBLESQL = process.env.TABLE || 'tables.sql';
const TABLES_SCHEMA_PATH = path.join(__dirname, TABBLESQL);

const app = express();
app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: true }));  
const PORT = process.env.CRSQL_PORT || 8080;

// ==========================================================
// CONFIGURAZIONE E ARCHIVI IN-MEMORY (PROTOTIPO)
// ==========================================================
const JWT_SECRET = process.env.JWT_SECRET || 'la_tua_chiave_segreta_molto_complessa';
const DB_STORAGE_PATH = path.join(__dirname, 'db_files');
// Percorso del binario cr-sqlite.so (DA VERIFICARE)
const CRSQLITE_EXTENSION_PATH = process.env.CRSQLITE_EXTENSION_PATH || path.join(__dirname, 'crsqlite.so'); 

// Archivio Utenti in-memory: { username: { passwordHash: '...', userId: '...' } }
const userCredentials = new Map();
// Pool di connessioni (o cache) per i DB aperti
const dbConnections = new Map();

// Assicura che la directory di archiviazione esista
if (!fs.existsSync(DB_STORAGE_PATH)) {
    fs.mkdirSync(DB_STORAGE_PATH);
}
// ==========================================================
// FUNZIONI UTILITY
// ==========================================================

/**
 * Funzione helper per eseguire una query asincrona
 */
function runQuery(db, sql, params = []) {
    return new Promise((resolve, reject) => {
        db.all(sql, params, (err, rows) => {
            if (err) return reject(err);
            resolve(rows);
        });
    });
}

/**
 * Funzione per aprire o creare un database utente
 */
async function getOrCreateUserDB(userId) {
    if (dbConnections.has(userId)) {
        return dbConnections.get(userId);
    }

    const dbPath = path.join(DB_STORAGE_PATH, `${userId}.sqlite`);
    const isNew = !fs.existsSync(dbPath);
    
    // Apri il database
    const db = new sqlite3.Database(dbPath, sqlite3.OPEN_READWRITE | sqlite3.OPEN_CREATE, (err) => {
        if (err) throw new Error(`Could not open database: ${err.message}`);
    });

    // Abilita l'estensione cr-sqlite
    await new Promise((resolve, reject) => {
        db.loadExtension(CRSQLITE_EXTENSION_PATH, (err) => {
            if (err) return reject(new Error(`Failed to load cr-sqlite extension: ${err.message}. Check CRSQLITE_EXTENSION_PATH.`));
            console.log(`[${userId}] cr-sqlite extension loaded.`);
            resolve();
        });
    });

    // Inizializza le tabelle se il DB è nuovo
    if (isNew) {
		 console.log(`[${userId}] Inizializzazione tabelle CRR leggendo da ${TABLES_SCHEMA_PATH}.`);
         
         // Leggi il contenuto del file tables.sql
         const schemaSql = fs.readFileSync(TABLES_SCHEMA_PATH, 'utf8');
         
         // Splitta le istruzioni SQL (supponendo che siano separate da punto e virgola)
         // Filtra le righe vuote o di commento
         const statements = schemaSql.split(';')
                                      .map(s => s.trim())
                                      .filter(s => s.length > 0);
         
         await runQuery(db, 'PRAGMA journal_mode=WAL;');

         // Esegui sequenzialmente ogni istruzione SQL
         for (const stmt of statements) {
             console.log(`[${userId}] Esecuzione SQL: ${stmt.substring(0, 50)}...`);
             await runQuery(db, stmt);
         }		
		 
		 initCrsqlTable(db);
    }

    dbConnections.set(userId, db);
    return db;
}


// ==========================================================
// MIDDLEWARE
// ==========================================================

/**
 * Autenticazione: Verifica il token nell'header 'Authorization' e estrae l'user_id
 */
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (token == null) return res.status(401).send({ error: 'Token non fornito o formato non valido.' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
             // Il token è scaduto o non valido
             return res.status(403).send({ error: 'Token non valido o scaduto.' });
        }
        req.user = user; // Contiene il payload JWT (es. { user_id: 'pippo123' })
        next();
    });
};

// ==========================================================
// ROTTE API
// ==========================================================

// 1. Pagina di Benvenuto
// ----------------------------------------------------------
app.get('/', (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <html>
        <head><title>Sync Gateway CR-SQLite</title></head>
        <body>
            <h1>Benvenuto nel Sync Gateway CR-SQLite</h1>
            <p>Sincronizzazione basata su CRDT isolata per utente.</p>
            <ul>
                <li><a href="/register">Registra un nuovo account</a></li>
                <li><a href="/login">Accedi e visualizza lo stato del DB</a></li>
            </ul>
        </body>
        </html>
    `);
});

app.get('/register', (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <html>
        <head><title>Registrazione</title></head>
        <body>
            <h2>Registrazione Nuovo Utente</h2>
            <form method="POST" action="/register">
                <label for="username">Username:</label><br>
                <input type="text" id="username" name="username" required><br><br>
                <label for="password">Password:</label><br>
                <input type="password" id="password" name="password" required><br><br>
                <button type="submit">Registra</button>
            </form>
            <p><a href="/">Torna alla Home</a></p>
        </body>
        </html>
    `);
});


app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    // ... (Logica di validazione e hashing identica a prima) ...
    if (!username || !password) {
        return res.status(400).send('Username e password sono richiesti.');
    }
    if (userCredentials.has(username)) {
        return res.status(409).send('Username già in uso.');
    }
    
    const userId = crypto.randomUUID(); 
    const passwordHash = crypto.createHash('sha256').update(password).digest('hex');

    userCredentials.set(username, { userId, passwordHash, username }); // Salviamo anche lo username
    
    try {
        console.log(`registrazione di: ${username} (ID: ${userId})`);
        await getOrCreateUserDB(userId);
        const token = jwt.sign({ user_id: userId, username: username }, JWT_SECRET, { expiresIn: '7d' });

        console.log(`Nuovo utente registrato: ${username} (ID: ${userId})`);

        // Risposta HTML che mostra il token
        res.status(201).send(`
            <!DOCTYPE html>
            <html>
            <head><title>Successo</title></head>
            <body>
                <h2>Registrazione Riuscita!</h2>
                <p>La sincronizzazione è attiva per l'utente <strong>${username}</strong>.</p>
                <p><strong>SALVA QUESTO TOKEN.</strong> Usalo come Bearer Token per le tue applicazioni Windows/Android/iOS nell'endpoint <code>/sync</code>.</p>
                <textarea rows="4" cols="50" readonly>${token}</textarea>
                <p><a href="/">Torna alla Home</a></p>
            </body>
            </html>
        `);

    } catch (error) {
        console.error('Errore durante la registrazione e inizializzazione DB:', error);
        res.status(500).send('Impossibile completare la registrazione.');
    }
});

// ... (nel file server.js) ...

// GET: Modulo per l'inserimento del JWT
app.get('/login', (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <html>
        <head><title>Stato Sincronizzazione</title></head>
        <body>
            <h2>Stato Database Utente</h2>
            <p>Inserisci il tuo JWT (ottenuto in fase di registrazione) per visualizzare i dettagli del tuo database isolato.</p>
            <form method="POST" action="/login">
                <label for="token">JWT Token:</label><br>
                <textarea id="token" name="token" rows="4" cols="50" required></textarea><br><br>
                <button type="submit">Visualizza Stato DB</button>
            </form>
            <p><a href="/">Torna alla Home</a></p>
        </body>
        </html>
    `);
});

// POST: Elabora il login/token e mostra lo stato
app.post('/login', async (req, res) => {
    const { token } = req.body;

    if (!token) {
        return res.status(400).send('Token non fornito.');
    }

    // 1. Verifica il Token (Manualmente, senza middleware)
    let user;
    try {
        user = jwt.verify(token, JWT_SECRET);
    } catch (err) {
        return res.status(403).send('Token non valido o scaduto.');
    }

	console.log(`login di: ${user.username} (ID: ${user.user_id})`);

    const userId = user.user_id;


	let db;
    try {
        db = await getOrCreateUserDB(userId);
        
        // A. CONTA DISPOSITIVI (SITE_ID)
        const devicesResult = await runQuery(db, 
            `SELECT COUNT(DISTINCT hex(site_id)) as device_count FROM crsql_changes;`
        );
        const deviceCount = devicesResult[0].device_count || 0;

        // B. DUMP DEL DB (Utilizzo della nuova funzione)
        const dbDumpSql = await generateSqlDump(db); // <-- NUOVA CHIAMATA

        // 2. Risposta HTML con lo stato
        res.send(`
            <!DOCTYPE html>
            <html>
            <head><title>Stato DB</title>
            <style>textarea { width: 90%; height: 300px; font-family: monospace; }</style>
            </head>
            <body>
                <h2>Stato del Database Isolato</h2>
                <p>Utente: <strong>${user.username || userId}</strong></p>
                <p>Dispositivi collegati (Site IDs unici): <strong>${deviceCount}</strong></p>
                
                <h3>Dump SQL Completo (escluse tabelle di controllo)</h3>
                <textarea readonly>${dbDumpSql}</textarea>
                
                <p><a href="/">Torna alla Home</a></p>
            </body>
            </html>
        `);

    } catch (error) {
        // ... (Gestione degli errori invariata) ...
    }
});


// 4. Rotta di Sincronizzazione (Invariata)
// ----------------------------------------------------------
app.post('/sync', authenticateToken, async (req, res) => {
    const userId = req.user.user_id;
    const { client_known_version, changes } = req.body; 

    // ... (Il resto della logica di sincronizzazione rimane come prima) ...
    // Esempio:
    if (typeof client_known_version === 'undefined' || !Array.isArray(changes)) {
        return res.status(400).send('Invalid sync payload.');
    }

    let db;
    try {
        db = await getOrCreateUserDB(userId);

        await runQuery(db, 'BEGIN TRANSACTION;');

        // 1. APPLICAZIONE DEI CAMBIAMENTI (UPLOAD)
        if (changes.length > 0) {
            const insertSql = `
                INSERT INTO crsql_changes ("table", "pk", "cid", "val", "col_version", "db_version", "site_id") 
                VALUES (?, ?, ?, ?, ?, ?, ?);
            `;
            
            await new Promise((resolve, reject) => {
                db.serialize(() => {
                    const stmt = db.prepare(insertSql);
                    changes.forEach(change => {
                        // Il formato del delta è [table, pk, cid, val, col_version, db_version, site_id]
                        stmt.run(change, (err) => {
                            if (err) console.error(`Errore Inserimento Delta: ${err.message}`);
                        });
                    });
                    stmt.finalize((err) => {
                        if (err) return reject(err);
                        resolve();
                    });
                });
            });
        }
        
        // 2. ESTRAZIONE DEI CAMBIAMENTI (DOWNLOAD)
        const serverChanges = await runQuery(db, 
            `SELECT "table", "pk", "cid", "val", "col_version", "db_version", "site_id" 
             FROM crsql_changes WHERE db_version > ?;`, 
            [client_known_version]
        ); 
        
        const [{ 'crsql_db_version()': db_version }] = await runQuery(db, "SELECT crsql_db_version();");
        
        await runQuery(db, 'COMMIT;');
        
        // 3. RISPOSTA
        res.json({
            changes: serverChanges,
            server_version: db_version 
        });

    } catch (error) {
        if (db) await runQuery(db, 'ROLLBACK;').catch(console.error);
        console.error(`Sync Error for User ${userId}:`, error);
        res.status(500).send('Synchronization failed.');
    }
});

app.listen(PORT, () => {
    console.log(`Sync Gateway running on http://localhost:${PORT}`);
});



/**
 * Genera una stringa SQL di dump per tutte le tabelle CRR dell'utente.
 */
async function generateSqlDump(db) {
    let sqlDump = '';
    
    // 1. Estrarre i nomi delle tabelle CRR (tutte le tabelle configurate per la replica)
    const allTables = await runQuery(db, "SELECT tbl_name FROM sqlite_master WHERE name NOT LIKE 'crsql\_%' ESCAPE '\\' AND type = 'table';");
    
    // Esempio: ['notes', 'projects', ...]
    const tableNames = allTables.map(row => row.tbl_name);

    for (const tableName of tableNames) {
		
        // 2. Estrarre lo schema (CREATE TABLE)
        const schemaResult = await runQuery(db, `SELECT sql FROM sqlite_master WHERE type='table' AND name=?`, [tableName]);
        if (schemaResult.length > 0) {
            sqlDump += `${schemaResult[0].sql};\n\n`;
        }
        
        // 3. Estrarre i dati e generare le istruzioni INSERT
        const dataRows = await runQuery(db, `SELECT * FROM ${tableName}`);
        
        dataRows.forEach(row => {
            const columns = Object.keys(row);
            const values = Object.values(row).map(val => {
                // Gestisce correttamente stringhe (tra apici) e numeri
                return (typeof val === 'string' || val === null) ? `'${val}'` : val;
            }).join(', ');
            
            sqlDump += `INSERT INTO ${tableName} (${columns.join(', ')}) VALUES (${values});\n`;
        });
        sqlDump += '\n';
    }

    return sqlDump;
}


/**
 * inizializza tutte le tabelle con crsql
 */
async function initCrsqlTable(db) {
    
    // 1. Estrarre i nomi delle tabelle CRR (tutte le tabelle configurate per la replica)
    const allTables = await runQuery(db, "SELECT tbl_name FROM sqlite_master WHERE name NOT LIKE 'crsql\_%' ESCAPE '\\' AND type = 'table';");
    
    // Esempio: ['notes', 'projects', ...]
    const tableNames = allTables.map(row => row.tbl_name);

    for (const tableName of tableNames) {
		console.log(`  crrql enable for: ${tableName}`);
        // inizializza con crsql
		await runQuery(db,  `select crsql_as_crr('${tableName}');`);
    }

    return;
}