async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(options.headers || {}),
    },
    credentials: 'include',
  });
  if (!response.ok) {
    let detail = 'Request failed';
    try {
      const data = await response.json();
      detail = data.detail || JSON.stringify(data);
    } catch (err) {
      detail = response.statusText;
    }
    throw new Error(detail);
  }
  if (response.headers.get('content-type')?.includes('application/json')) {
    return response.json();
  }
  return response.text();
}

const loginForm = document.getElementById('login-form');
const logoutBtn = document.getElementById('logout-btn');
const loginError = document.getElementById('login-error');
const userInfo = document.getElementById('user-info');
const userKeySection = document.getElementById('user-key-section');
const adminSection = document.getElementById('admin-section');
const myKeyDisplay = document.getElementById('my-key-display');
const generateKeyBtn = document.getElementById('generate-key');
const deleteKeyBtn = document.getElementById('delete-key');
const createAppForm = document.getElementById('create-app-form');
const createAppError = document.getElementById('create-app-error');
const appKeysTableBody = document.querySelector('#app-keys-table tbody');

async function refreshUser() {
  try {
    const me = await api('/me');
    loginForm.hidden = true;
    logoutBtn.hidden = false;
    userInfo.hidden = false;
    userInfo.textContent = `${me.username} (${me.email || 'no email'}) - ${me.is_admin ? 'admin' : 'user'}`;
    userKeySection.hidden = false;
    loginError.textContent = '';
    await refreshMyKey();
    if (me.is_admin) {
      adminSection.hidden = false;
      await refreshAppKeys();
    } else {
      adminSection.hidden = true;
    }
  } catch (err) {
    loginForm.hidden = false;
    logoutBtn.hidden = true;
    userInfo.hidden = true;
    userKeySection.hidden = true;
    adminSection.hidden = true;
  }
}

async function refreshMyKey() {
  try {
    const data = await api('/me/key');
    if (!data.subject) {
      myKeyDisplay.textContent = 'No key';
    } else {
      myKeyDisplay.textContent = JSON.stringify(data, null, 2);
    }
  } catch (err) {
    myKeyDisplay.textContent = err.message;
  }
}

async function refreshAppKeys() {
  try {
    const data = await api('/admin/keys');
    appKeysTableBody.innerHTML = '';
    data.items.forEach(item => {
      const row = document.createElement('tr');
      row.innerHTML = `
        <td>${item.subject}</td>
        <td>${item.key}</td>
        <td>${item.created_at}</td>
        <td>${item.expires_at ?? ''}</td>
        <td>
          <button data-action="rotate" data-name="${item.subject.replace('app:', '')}">Rotate</button>
          <button data-action="delete" data-name="${item.subject.replace('app:', '')}">Delete</button>
        </td>
      `;
      appKeysTableBody.appendChild(row);
    });
  } catch (err) {
    createAppError.textContent = err.message;
  }
}

loginForm?.addEventListener('submit', async (event) => {
  event.preventDefault();
  const formData = new FormData(loginForm);
  try {
    await api('/auth/login', {
      method: 'POST',
      body: JSON.stringify({
        username: formData.get('username'),
        password: formData.get('password'),
      }),
    });
    loginError.textContent = '';
    await refreshUser();
  } catch (err) {
    loginError.textContent = err.message;
  }
});

logoutBtn?.addEventListener('click', async () => {
  await api('/auth/logout', { method: 'POST' });
  loginForm.hidden = false;
  logoutBtn.hidden = true;
  userInfo.hidden = true;
  userKeySection.hidden = true;
  adminSection.hidden = true;
});

generateKeyBtn?.addEventListener('click', async () => {
  try {
    const data = await api('/me/key:regenerate', { method: 'POST' });
    myKeyDisplay.textContent = JSON.stringify(data, null, 2);
  } catch (err) {
    myKeyDisplay.textContent = err.message;
  }
});

deleteKeyBtn?.addEventListener('click', async () => {
  try {
    await api('/me/key', { method: 'DELETE' });
    myKeyDisplay.textContent = 'No key';
  } catch (err) {
    myKeyDisplay.textContent = err.message;
  }
});

createAppForm?.addEventListener('submit', async (event) => {
  event.preventDefault();
  const formData = new FormData(createAppForm);
  try {
    await api('/admin/app-keys', {
      method: 'POST',
      body: JSON.stringify({
        name: formData.get('name'),
        key: formData.get('key') || undefined,
      }),
    });
    createAppForm.reset();
    createAppError.textContent = '';
    await refreshAppKeys();
  } catch (err) {
    createAppError.textContent = err.message;
  }
});

appKeysTableBody?.addEventListener('click', async (event) => {
  const target = event.target;
  if (!(target instanceof HTMLButtonElement)) {
    return;
  }
  const name = target.dataset.name;
  const action = target.dataset.action;
  try {
    if (action === 'rotate') {
      await api(`/admin/app-keys/${name}`, { method: 'PUT' });
    } else if (action === 'delete') {
      await api(`/admin/app-keys/${name}`, { method: 'DELETE' });
    }
    await refreshAppKeys();
  } catch (err) {
    createAppError.textContent = err.message;
  }
});

refreshUser();
