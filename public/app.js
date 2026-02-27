
function validateUsername(value) {
  return /^[a-zA-Z0-9_]{3,30}$/.test(value.trim());
}

function validateEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value.trim());
}

function validatePassword(value) {
  return value.length >= 8 && value.length <= 72;
}


function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = String(str); 
  return div.innerHTML;
}

function showAlert(message, type = 'error') {
  const box = document.getElementById('alertBox');
  box.textContent = message; 
  box.className = `alert ${type} show`;
}

function hideAlert() {
  document.getElementById('alertBox').className = 'alert';
}

function setLoading(btnId, loading) {
  const btn = document.getElementById(btnId);
  btn.disabled = loading;
  if (btnId === 'loginBtn') {
    btn.textContent = loading ? 'Ingresando...' : 'Ingresar';
  } else {
    btn.textContent = loading ? 'Creando cuenta...' : 'Crear cuenta';
  }
}


function switchTab(tab) {
  const isLogin = tab === 'login';

  document.getElementById('tabLogin').classList.toggle('active', isLogin);
  document.getElementById('tabRegister').classList.toggle('active', !isLogin);
  document.getElementById('loginForm').style.display = isLogin ? '' : 'none';
  document.getElementById('registerForm').style.display = isLogin ? 'none' : '';
  document.getElementById('usersPanel').style.display = 'none';

  hideAlert();
}



async function handleLogin(event) {
  event.preventDefault();
  hideAlert();

  const username = document.getElementById('loginUser').value;
  const password = document.getElementById('loginPass').value;

  // Validación client-side
  if (!validateUsername(username)) {
    return showAlert('Usuario inválido: solo letras, números y _ (3–30 caracteres).');
  }
  if (!validatePassword(password)) {
    return showAlert('Contraseña inválida: mínimo 8, máximo 72 caracteres.');
  }

  setLoading('loginBtn', true);

  try {
    const response = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: username.trim(),
        password: password,
      }),
    });

    const data = await response.json();

    if (data.success) {
      showAlert('✓ ' + data.message, 'success');
      loadUsers();
    } else {
      showAlert(data.message || 'Error al iniciar sesión.');
    }

  } catch (error) {
    showAlert('Error de conexión con el servidor.');
  } finally {
    setLoading('loginBtn', false);
  }
}

async function handleRegister(event) {
  event.preventDefault();
  hideAlert();

  const username = document.getElementById('regUser').value;
  const email    = document.getElementById('regEmail').value;
  const password = document.getElementById('regPass').value;

  if (!validateUsername(username)) {
    return showAlert('Usuario inválido: solo letras, números y _ (3–30 caracteres).');
  }
  if (!validateEmail(email)) {
    return showAlert('Ingresa un correo electrónico válido.');
  }
  if (!validatePassword(password)) {
    return showAlert('Contraseña: mínimo 8, máximo 72 caracteres.');
  }

  setLoading('registerBtn', true);

  try {
    const response = await fetch('/api/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: username.trim(),
        email:    email.trim().toLowerCase(),
        password: password,
      }),
    });

    const data = await response.json();

    if (data.success) {
      showAlert('✓ ' + data.message, 'success');
      document.getElementById('registerForm').reset();
      loadUsers();
    } else {
      showAlert(data.message || 'Error al registrar usuario.');
    }

  } catch (error) {
    showAlert('Error de conexión con el servidor.');
  } finally {
    setLoading('registerBtn', false);
  }
}


async function loadUsers() {
  try {
    const response = await fetch('/api/users');
    const data = await response.json();

    if (!data.success) return;

    const panel = document.getElementById('usersPanel');
    const list  = document.getElementById('usersList');

    panel.style.display = '';
    list.innerHTML = '';

    data.users.forEach(function(user) {
      const row = document.createElement('div');
      row.className = 'user-row';

      const initial = escapeHtml(user.username.charAt(0).toUpperCase());
      const name    = escapeHtml(user.username);
      const email   = escapeHtml(user.email);

      row.innerHTML = `
        <div class="user-avatar">${initial}</div>
        <div>
          <div class="user-name">${name}</div>
          <div class="user-email">${email}</div>
        </div>
      `;

      list.appendChild(row);
    });

  } catch (error) {
    console.error('Error cargando usuarios:', error);
  }
}
