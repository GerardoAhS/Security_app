/**
 * server.js — Backend seguro con Node.js
 *
 * Prácticas de seguridad implementadas:
 * 1. Validación de entrada (server-side)
 * 2. Queries parametrizadas (protección contra SQL Injection)
 * 3. Manejo de errores personalizado (no expone internos al cliente)
 * 4. Output encoding (protección contra XSS)
 * 5. Contraseñas hasheadas con bcrypt (salt 12)
 * 6. Rate limiting básico por IP
 * 7. Security headers
 */

const http = require('http');
const path = require('path');
const fs   = require('fs');
const url  = require('url');

// ─── Base de datos JSON (puro Node.js, sin compilación) ──────────────────
const DB_PATH = path.join(__dirname, 'users_db.json');

function loadDB() {
  if (!fs.existsSync(DB_PATH)) {
    fs.writeFileSync(DB_PATH, JSON.stringify({ users: [] }, null, 2));
  }
  return JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
}

function saveDB(data) {
  fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2));
}

// ─── Queries parametrizadas (equivalente a Prepared Statements) ──────────
// Nunca se concatenan strings del usuario en las búsquedas.
// Siempre comparamos por valor exacto — esto previene SQL/NoSQL Injection.

const db = {

  findByUsername(username) {
    const data = loadDB();
    // Equivalente a: SELECT * FROM users WHERE username = ?
    return data.users.find(u => u.username === username) || null;
  },

  findByEmail(email) {
    const data = loadDB();
    // Equivalente a: SELECT * FROM users WHERE email = ?
    return data.users.find(u => u.email === email) || null;
  },

  insertUser(username, email, hashedPassword) {
    const data = loadDB();
    const newUser = {
      id:         Date.now(),
      username:   username,
      email:      email,
      password:   hashedPassword, // nunca texto plano
      created_at: new Date().toISOString(),
    };
    data.users.push(newUser);
    saveDB(data);
    return newUser;
  },

  getAllUsers() {
    const data = loadDB();
    // Nunca devolver el campo password al cliente
    return data.users.map(function(u) {
      return { id: u.id, username: u.username, email: u.email, created_at: u.created_at };
    });
  },

};

// ─── bcryptjs (100% JavaScript, sin compilación) ─────────────────────────
let bcrypt;
try {
  bcrypt = require('bcryptjs');
} catch (e) {
  console.error('❌ Instala la dependencia: npm install bcryptjs');
  process.exit(1);
}

// ─── Rate Limiting simple ─────────────────────────────────────────────────
const rateLimitMap = new Map();

function rateLimit(ip) {
  const MAX_REQUESTS = 20;
  const WINDOW_MS    = 60 * 1000; // 1 minuto
  const now          = Date.now();
  const entry        = rateLimitMap.get(ip) || { count: 0, start: now };

  if (now - entry.start > WINDOW_MS) {
    rateLimitMap.set(ip, { count: 1, start: now });
    return false; // no bloqueado
  }

  entry.count++;
  rateLimitMap.set(ip, entry);
  return entry.count > MAX_REQUESTS; // true = bloqueado
}

// ─── Validación de entrada (server-side) ─────────────────────────────────
// La validación client-side es conveniente pero NO es segura por sí sola.
// SIEMPRE se debe validar también en el servidor.

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

// ─── Output Encoding (previene XSS) ──────────────────────────────────────
function escapeHtml(str) {
  return String(str)
    .replace(/&/g,  '&amp;')
    .replace(/</g,  '&lt;')
    .replace(/>/g,  '&gt;')
    .replace(/"/g,  '&quot;')
    .replace(/'/g,  '&#x27;');
}

// ─── Helpers de respuesta HTTP ────────────────────────────────────────────
function sendJSON(res, statusCode, data) {
  res.writeHead(statusCode, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

function sendError(res, statusCode, message) {
  // Controlador de errores personalizado:
  // El cliente recibe un mensaje claro pero genérico.
  // Los detalles técnicos solo se imprimen en la consola del servidor.
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

// ─── Tipos MIME para archivos estáticos ──────────────────────────────────
const MIME_TYPES = {
  '.html': 'text/html',
  '.css':  'text/css',
  '.js':   'application/javascript',
  '.json': 'application/json',
  '.ico':  'image/x-icon',
};

// ─── Servidor HTTP ────────────────────────────────────────────────────────
const server = http.createServer(async function(req, res) {
  const clientIp  = req.socket.remoteAddress;
  const parsedUrl = url.parse(req.url, true);
  const pathname  = parsedUrl.pathname;

  // Rate limiting
  if (rateLimit(clientIp)) {
    return sendError(res, 429, 'Demasiadas solicitudes. Espera un momento.');
  }

  // Security headers
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');

  // ── Archivos estáticos (HTML, CSS, JS) ─────────────────────────────────
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

  // ── POST /api/register ─────────────────────────────────────────────────
  if (req.method === 'POST' && pathname === '/api/register') {
    try {
      const body = await parseBody(req);

      // 1. Validación de entrada
      const errors = validateInput({ username: body.username, email: body.email, password: body.password });
      if (errors.length > 0) {
        return sendError(res, 400, errors.join(' '));
      }

      const username = body.username.trim();
      const email    = body.email.trim().toLowerCase();
      const password = body.password;

      // 2. Verificar que no exista (query parametrizada)
      if (db.findByUsername(username)) {
        return sendError(res, 409, 'Ese nombre de usuario ya existe.');
      }
      if (db.findByEmail(email)) {
        return sendError(res, 409, 'Ese correo ya está registrado.');
      }

      // 3. Hashear contraseña con bcrypt (salt 12)
      const hashedPassword = await bcrypt.hash(password, 12);

      // 4. Guardar usuario
      db.insertUser(username, email, hashedPassword);

      return sendJSON(res, 201, {
        success: true,
        message: 'Usuario "' + escapeHtml(username) + '" registrado exitosamente.',
      });

    } catch (err) {
      // Error interno: solo se imprime en consola, no se expone al cliente
      console.error('[REGISTER ERROR]', err.message);
      return sendError(res, 500, 'Error interno del servidor.');
    }
  }

  // ── POST /api/login ────────────────────────────────────────────────────
  if (req.method === 'POST' && pathname === '/api/login') {
    try {
      const body = await parseBody(req);

      // 1. Validación de entrada
      const errors = validateInput({ username: body.username, password: body.password });
      if (errors.length > 0) {
        return sendError(res, 400, errors.join(' '));
      }

      const username = body.username.trim();
      const password = body.password;

      // 2. Buscar usuario (query parametrizada)
      const user = db.findByUsername(username);

      // 3. Mensaje genérico si falla (no revelar si el usuario existe o no)
      if (!user) {
        return sendError(res, 401, 'Credenciales incorrectas.');
      }

      // 4. Comparar contraseña con hash (bcrypt)
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

  // ── GET /api/users ─────────────────────────────────────────────────────
  if (req.method === 'GET' && pathname === '/api/users') {
    try {
      return sendJSON(res, 200, { success: true, users: db.getAllUsers() });
    } catch (err) {
      console.error('[USERS ERROR]', err.message);
      return sendError(res, 500, 'Error interno del servidor.');
    }
  }

  // ── 404 personalizado ──────────────────────────────────────────────────
  sendError(res, 404, 'Ruta no encontrada.');
});

// ─── Iniciar servidor ─────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;

server.listen(PORT, function() {
  console.log('\n✅  Servidor corriendo en http://localhost:' + PORT);
  console.log('\n🔒  Prácticas de seguridad activas:');
  console.log('     1. Validación de entrada (server-side + client-side)');
  console.log('     2. Queries parametrizadas (anti SQL Injection)');
  console.log('     3. Passwords hasheadas con bcrypt (salt 12)');
  console.log('     4. Manejo de errores personalizado');
  console.log('     5. Output encoding (anti XSS)');
  console.log('     6. Rate limiting (20 req/min por IP)');
  console.log('     7. Security headers\n');
});
