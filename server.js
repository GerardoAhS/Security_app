

const http = require('http');
const path = require('path');
const fs   = require('fs');
const url  = require('url');

let initSqlJs;
try {
  initSqlJs = require('sql.js');
} catch (e) {
  console.error('❌ Instala la dependencia: npm install sql.js bcryptjs');
  process.exit(1);
}

const DB_PATH = path.join(__dirname, 'users.sqlite');

let sqlDb; 


async function initDatabase() {
  const SQL = await initSqlJs();

  if (fs.existsSync(DB_PATH)) {
    const fileBuffer = fs.readFileSync(DB_PATH);
    sqlDb = new SQL.Database(fileBuffer);
  } else {
    sqlDb = new SQL.Database();
  }

  sqlDb.run(`
    CREATE TABLE IF NOT EXISTS users (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      username   TEXT UNIQUE NOT NULL,
      email      TEXT UNIQUE NOT NULL,
      password   TEXT NOT NULL,
      created_at TEXT DEFAULT (datetime('now'))
    )
  `);

  saveDatabase();
  console.log('✅  Base de datos SQLite lista.');
}


function saveDatabase() {
  const data = sqlDb.export();
  fs.writeFileSync(DB_PATH, Buffer.from(data));
}


const db = {

  findByUsername(username) {
    const stmt   = sqlDb.prepare('SELECT * FROM users WHERE username = :username');
    const result = stmt.getAsObject({ ':username': username });
    stmt.free();
    return result.id ? result : null;
  },

  findByEmail(email) {
    const stmt   = sqlDb.prepare('SELECT * FROM users WHERE email = :email');
    const result = stmt.getAsObject({ ':email': email });
    stmt.free();
    return result.id ? result : null;
  },

  insertUser(username, email, hashedPassword) {
    const stmt = sqlDb.prepare(
      'INSERT INTO users (username, email, password) VALUES (:username, :email, :password)'
    );
    stmt.run({ ':username': username, ':email': email, ':password': hashedPassword });
    stmt.free();
    saveDatabase(); 
  },

  getAllUsers() {
    const stmt    = sqlDb.prepare('SELECT id, username, email, created_at FROM users');
    const users   = [];
    while (stmt.step()) {
      users.push(stmt.getAsObject());
    }
    stmt.free();
    return users;
  },

};

let bcrypt;
try {
  bcrypt = require('bcryptjs');
} catch (e) {
  console.error('❌ Instala la dependencia: npm install bcryptjs');
  process.exit(1);
}

const rateLimitMap = new Map();

function rateLimit(ip) {
  const MAX_REQUESTS = 20;
  const WINDOW_MS    = 60 * 1000; 
  const now          = Date.now();
  const entry        = rateLimitMap.get(ip) || { count: 0, start: now };

  if (now - entry.start > WINDOW_MS) {
    rateLimitMap.set(ip, { count: 1, start: now });
    return false; 
  }

  entry.count++;
  rateLimitMap.set(ip, entry);
  return entry.count > MAX_REQUESTS; 
}


function validateInput(data) {
  const errors = [];

  if (!data.username || typeof data.username !== 'string') {
    errors.push('El username es requerido.');
  } else if (!/^[a-zA-Z0-9_]{3,30}$/.test(data.username.trim())) {
    errors.push('Username: solo letras, números y _ (3–30 caracteres).');
  }

  if (data.email !== undefined) {
    if (!data.email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(data.email.trim())) {
      errors.push('El email no es válido.');
    }
  }

  if (!data.password || typeof data.password !== 'string') {
    errors.push('La contraseña es requerida.');
  } else if (data.password.length < 8 || data.password.length > 72) {
    errors.push('Contraseña: mínimo 8, máximo 72 caracteres.');
  }

  return errors;
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g,  '&amp;')
    .replace(/</g,  '&lt;')
    .replace(/>/g,  '&gt;')
    .replace(/"/g,  '&quot;')
    .replace(/'/g,  '&#x27;');
}

function sendJSON(res, statusCode, data) {
  res.writeHead(statusCode, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

function sendError(res, statusCode, message) {
  sendJSON(res, statusCode, { success: false, message: message });
}

function parseBody(req) {
  return new Promise(function(resolve, reject) {
    let body = '';
    req.on('data', function(chunk) {
      body += chunk.toString();
      if (body.length > 10000) reject(new Error('Payload demasiado grande'));
    });
    req.on('end', function() {
      try { resolve(JSON.parse(body)); }
      catch { reject(new Error('JSON inválido')); }
    });
  });
}

const MIME_TYPES = {
  '.html': 'text/html',
  '.css':  'text/css',
  '.js':   'application/javascript',
  '.json': 'application/json',
  '.ico':  'image/x-icon',
};

const server = http.createServer(async function(req, res) {
  const clientIp  = req.socket.remoteAddress;
  const parsedUrl = url.parse(req.url, true);
  const pathname  = parsedUrl.pathname;

  if (rateLimit(clientIp)) {
    return sendError(res, 429, 'Demasiadas solicitudes. Espera un momento.');
  }

  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');

  if (req.method === 'GET' && !pathname.startsWith('/api/')) {
    let filePath = path.join(__dirname, 'public', pathname === '/' ? 'index.html' : pathname);
    const ext    = path.extname(filePath);
    const mime   = MIME_TYPES[ext] || 'text/plain';

    try {
      const content = fs.readFileSync(filePath);
      res.writeHead(200, { 'Content-Type': mime });
      return res.end(content);
    } catch {
      return sendError(res, 404, 'Archivo no encontrado.');
    }
  }

  if (req.method === 'POST' && pathname === '/api/register') {
    try {
      const body = await parseBody(req);

      const errors = validateInput({ username: body.username, email: body.email, password: body.password });
      if (errors.length > 0) {
        return sendError(res, 400, errors.join(' '));
      }

      const username = body.username.trim();
      const email    = body.email.trim().toLowerCase();
      const password = body.password;

      if (db.findByUsername(username)) {
        return sendError(res, 409, 'Ese nombre de usuario ya existe.');
      }
      if (db.findByEmail(email)) {
        return sendError(res, 409, 'Ese correo ya está registrado.');
      }

      const hashedPassword = await bcrypt.hash(password, 12);

      db.insertUser(username, email, hashedPassword);

      return sendJSON(res, 201, {
        success: true,
        message: 'Usuario "' + escapeHtml(username) + '" registrado exitosamente.',
      });

    } catch (err) {
      console.error('[REGISTER ERROR]', err.message);
      return sendError(res, 500, 'Error interno del servidor.');
    }
  }

  if (req.method === 'POST' && pathname === '/api/login') {
    try {
      const body = await parseBody(req);

      const errors = validateInput({ username: body.username, password: body.password });
      if (errors.length > 0) {
        return sendError(res, 400, errors.join(' '));
      }

      const username = body.username.trim();
      const password = body.password;

      const user = db.findByUsername(username);

      if (!user) {
        return sendError(res, 401, 'Credenciales incorrectas.');
      }

      const passwordMatch = await bcrypt.compare(password, user.password);
      if (!passwordMatch) {
        return sendError(res, 401, 'Credenciales incorrectas.');
      }

      return sendJSON(res, 200, {
        success: true,
        message: '¡Bienvenido, ' + escapeHtml(user.username) + '!',
        user: { id: user.id, username: user.username, email: user.email },
      });

    } catch (err) {
      console.error('[LOGIN ERROR]', err.message);
      return sendError(res, 500, 'Error interno del servidor.');
    }
  }

  if (req.method === 'GET' && pathname === '/api/users') {
    try {
      return sendJSON(res, 200, { success: true, users: db.getAllUsers() });
    } catch (err) {
      console.error('[USERS ERROR]', err.message);
      return sendError(res, 500, 'Error interno del servidor.');
    }
  }

  sendError(res, 404, 'Ruta no encontrada.');
});

const PORT = process.env.PORT || 3000;

initDatabase().then(function() {
  server.listen(PORT, function() {
    console.log('\nServidor corriendo en http://localhost:' + PORT);
    console.log('\nPrácticas de seguridad activas:');
    console.log('     1. Validación de entrada (server-side + client-side)');
    console.log('     2. Prepared Statements SQLite (anti SQL Injection)');
    console.log('     3. Passwords hasheadas con bcrypt (salt 12)');
    console.log('     4. Manejo de errores personalizado');
    console.log('     5. Output encoding (anti XSS)');
    console.log('     6. Rate limiting (20 req/min por IP)');
    console.log('     7. Security headers\n');
  });
}).catch(function(err) {
  console.error('Error iniciando base de datos:', err.message);
  process.exit(1);
});
