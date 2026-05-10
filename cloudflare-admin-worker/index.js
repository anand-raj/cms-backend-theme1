// Admin Worker — Cloudflare Workers + D1
//
// Endpoints:
//   GET    /admin/admins       — List all admins (any admin)
//   POST   /admin/admins       — Add an admin (owner only)
//   DELETE /admin/admins/:id   — Remove an admin (owner only)
//
// Required environment variables (set in Cloudflare dashboard or wrangler.toml):
//   ADMIN_URL    (plain)     Admin portal origin for CORS
//   DEV_ORIGIN   (plain)     Optional: http://localhost:5173 for local dev only
//
// D1 database binding: DB

// ---------------------------------------------------------------------------
// CORS
// ---------------------------------------------------------------------------

function adminCorsHeaders(origin, env) {
  const allowed = [env.ADMIN_URL, env.DEV_ORIGIN].filter(Boolean);
  if (!allowed.includes(origin)) return {};
  return {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  };
}

function jsonOk(data, origin, env) {
  return new Response(JSON.stringify(data), {
    headers: { 'Content-Type': 'application/json', ...adminCorsHeaders(origin, env) },
  });
}

function jsonErr(message, status, origin, env) {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: { 'Content-Type': 'application/json', ...adminCorsHeaders(origin, env) },
  });
}

// ---------------------------------------------------------------------------
// Auth — D1 admins table, SHA-256 token hash cached for 5 min
// ---------------------------------------------------------------------------

async function validateAdminToken(ghToken, env) {
  const enc     = new TextEncoder();
  const hashBuf = await crypto.subtle.digest('SHA-256', enc.encode(ghToken));
  const hashHex = Array.from(new Uint8Array(hashBuf)).map(b => b.toString(16).padStart(2, '0')).join('');
  const cacheKey = new Request(`https://internal-admin-auth-cache/${hashHex}`);
  const cache    = caches.default;

  const cached = await cache.match(cacheKey);
  if (cached) {
    const text = await cached.text();
    if (text === 'none') return null;
    try { return JSON.parse(text); } catch { return null; }
  }

  async function storeResult(result) {
    await cache.put(cacheKey, new Response(result ? JSON.stringify(result) : 'none', {
      headers: { 'Cache-Control': 'public, max-age=300' },
    }));
    return result;
  }

  try {
    const userRes = await fetch('https://api.github.com/user', {
      headers: {
        Authorization: `token ${ghToken}`,
        'User-Agent': 'cms-admin-worker',
        Accept: 'application/vnd.github+json',
      },
    });
    if (!userRes.ok) return storeResult(null);
    const { login } = await userRes.json();
    if (!login) return storeResult(null);

    const row = await env.DB.prepare(
      `SELECT role, section FROM admins WHERE github_login = ?`
    ).bind(login).first();

    return storeResult(row ? { role: row.role, section: row.section || null } : null);
  } catch {
    return null; // network error — do not cache
  }
}

async function requireAdmin(request, env) {
  const authHeader = request.headers.get('Authorization') || '';
  if (authHeader.startsWith('token ') || authHeader.startsWith('Bearer ')) {
    const ghToken = authHeader.replace(/^(token|Bearer)\s+/, '');
    return validateAdminToken(ghToken, env);
  }
  return null;
}

// ---------------------------------------------------------------------------
// Route: GET /admin/admins
// ---------------------------------------------------------------------------

async function handleListAdmins(request, env) {
  const origin = request.headers.get('Origin') || '';
  if (!await requireAdmin(request, env)) {
    return jsonErr('Unauthorized.', 401, origin, env);
  }

  const { results } = await env.DB.prepare(
    `SELECT id, github_login, role, section, added_at FROM admins ORDER BY added_at DESC`
  ).all();

  return jsonOk(results, origin, env);
}

// ---------------------------------------------------------------------------
// Route: POST /admin/admins
// ---------------------------------------------------------------------------

async function handleAddAdmin(request, env) {
  const origin = request.headers.get('Origin') || '';
  const admin  = await requireAdmin(request, env);
  if (admin?.role !== 'owner') {
    return jsonErr('Only owners can add admins.', 403, origin, env);
  }

  let body;
  try { body = await request.json(); } catch {
    return jsonErr('Invalid JSON.', 400, origin, env);
  }

  const github_login = String(body.github_login || '').trim().toLowerCase().slice(0, 100);
  const newRole      = ['owner', 'moderator', 'section_editor'].includes(body.role) ? body.role : 'moderator';
  const newSection   = newRole === 'section_editor'
    ? String(body.section || '').trim().slice(0, 100)
    : null;

  if (!github_login) return jsonErr('github_login is required.', 400, origin, env);
  if (newRole === 'section_editor' && !newSection) {
    return jsonErr('section is required for section_editor role.', 400, origin, env);
  }

  try {
    await env.DB.prepare(
      `INSERT INTO admins (github_login, role, section, added_at) VALUES (?, ?, ?, ?)`
    ).bind(github_login, newRole, newSection, new Date().toISOString()).run();
  } catch (e) {
    if (e.message.includes('UNIQUE constraint failed')) {
      return jsonErr('This admin already exists.', 409, origin, env);
    }
    throw e;
  }

  return jsonOk({ ok: true }, origin, env);
}

// ---------------------------------------------------------------------------
// Route: DELETE /admin/admins/:id
// ---------------------------------------------------------------------------

async function handleRemoveAdmin(request, url, env) {
  const origin = request.headers.get('Origin') || '';
  const admin  = await requireAdmin(request, env);
  if (admin?.role !== 'owner') {
    return jsonErr('Only owners can remove admins.', 403, origin, env);
  }

  const id = parseInt(url.pathname.split('/').pop(), 10);
  if (!id) return jsonErr('Invalid id.', 400, origin, env);

  // Prevent removing the last owner
  const { results: owners } = await env.DB.prepare(
    `SELECT id FROM admins WHERE role = 'owner'`
  ).all();
  if (owners.length === 1 && owners[0].id === id) {
    return jsonErr('Cannot remove the last owner.', 400, origin, env);
  }

  await env.DB.prepare(`DELETE FROM admins WHERE id = ?`).bind(id).run();

  return jsonOk({ ok: true }, origin, env);
}

// ---------------------------------------------------------------------------
// Main fetch handler
// ---------------------------------------------------------------------------

export default {
  async fetch(request, env) {
    const url    = new URL(request.url);
    const origin = request.headers.get('Origin') || '';

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: adminCorsHeaders(origin, env) });
    }

    if (request.method === 'DELETE' && url.pathname.startsWith('/admin/admins/')) {
      return handleRemoveAdmin(request, url, env);
    }

    switch (`${request.method} ${url.pathname}`) {
      case 'GET /admin/admins':  return handleListAdmins(request, env);
      case 'POST /admin/admins': return handleAddAdmin(request, env);
      default:                   return new Response('Not found.', { status: 404 });
    }
  },
};

