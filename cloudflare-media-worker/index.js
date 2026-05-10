// Media Worker — Cloudflare Workers + R2 + D1
//
// Endpoints:
//   GET    /media              — List all media objects (admin portal)
//   POST   /media/upload       — Upload a file via multipart form-data (stored via R2 binding)
//   DELETE /media/:key         — Delete a media object (owner/moderator only)
//
// Upload flow:
//   1. Browser POSTs multipart FormData (field: "file") to /media/upload with GitHub token
//   2. Worker verifies token via GitHub API + checks admins D1 table
//   3. Worker writes file to R2 via binding, returns { publicUrl, key }
//   4. Browser copies the public URL into Sveltia CMS
//
// Plain vars (wrangler.toml):
//   R2_PUBLIC_URL         Public base URL e.g. https://pub-xxx.r2.dev
//   SITE_URL              Site origin for CORS
//   ADMIN_URL             Admin portal origin for CORS
//
// Bindings:
//   DB            D1 database (shared cms database — admins table for auth)
//   MEDIA_BUCKET  R2 bucket (used for upload, list, and delete)

// ---------------------------------------------------------------------------
// CORS helpers
// ---------------------------------------------------------------------------

function corsHeaders(origin, env) {
  const allowed = [env.SITE_URL, env.ADMIN_URL, env.DEV_ORIGIN].filter(Boolean);
  if (!allowed.includes(origin)) return {};   // unknown origin — omit CORS header entirely
  return {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400',
  };
}

function jsonOk(data, origin, env) {
  return new Response(JSON.stringify(data), {
    headers: { 'Content-Type': 'application/json', ...corsHeaders(origin, env) },
  });
}

function jsonErr(message, status, origin, env) {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: { 'Content-Type': 'application/json', ...corsHeaders(origin, env) },
  });
}

// ---------------------------------------------------------------------------
// Admin auth — D1 admins table (same pattern as all other CMS workers)
// ---------------------------------------------------------------------------

async function validateAdminToken(ghToken, env) {
  const enc     = new TextEncoder();
  const hashBuf = await crypto.subtle.digest('SHA-256', enc.encode(ghToken));
  const hashHex = Array.from(new Uint8Array(hashBuf)).map(b => b.toString(16).padStart(2, '0')).join('');
  const cacheKey = new Request(`https://internal-admin-auth-cache/${hashHex}`);
  const cache    = caches.default;
  const cached   = await cache.match(cacheKey);
  if (cached) {
    const text = await cached.text();
    return text === 'none' ? null : text;
  }

  async function storeResult(role) {
    await cache.put(cacheKey, new Response(role ?? 'none', {
      headers: { 'Cache-Control': 'public, max-age=300' },
    }));
    return role;
  }

  try {
    const userRes = await fetch('https://api.github.com/user', {
      headers: {
        Authorization: `token ${ghToken}`,
        'User-Agent': 'cms-media-worker',
        Accept: 'application/vnd.github+json',
      },
    });
    if (!userRes.ok) return storeResult(null);
    const { login } = await userRes.json();
    if (!login) return storeResult(null);

    const row = await env.DB.prepare(
      'SELECT role FROM admins WHERE github_login = ?'
    ).bind(login).first();

    return storeResult(row ? row.role : null);
  } catch {
    return null;
  }
}

async function requireAdmin(request, env) {
  const authHeader = request.headers.get('Authorization') || '';
  if (authHeader.startsWith('token ') || authHeader.startsWith('Bearer ')) {
    const ghToken = authHeader.replace(/^(token|Bearer)\s+/, '').trim();
    if (!ghToken) return null;
    return validateAdminToken(ghToken, env);
  }
  return null;
}

// (Presigned URL logic removed — uploads go through the Worker via R2 binding)

// ---------------------------------------------------------------------------
// File validation
// ---------------------------------------------------------------------------

const ALLOWED_EXTENSIONS = new Set([
  'jpg', 'jpeg', 'png', 'webp', 'gif', 'avif',
  // svg intentionally excluded — SVGs can embed <script> tags and execute JS
  // when opened directly in a browser (XSS / content injection risk)
  'mp4', 'webm',
  'pdf',
]);

const ALLOWED_CONTENT_TYPES = new Set([
  'image/jpeg', 'image/png', 'image/webp', 'image/gif', 'image/avif',
  // image/svg+xml excluded — see note above
  'video/mp4', 'video/webm',
  'application/pdf',
]);

function validateFile(filename, contentType) {
  const ext = filename.split('.').pop()?.toLowerCase() ?? '';
  if (!ALLOWED_EXTENSIONS.has(ext))        return 'File type not allowed.';
  if (!ALLOWED_CONTENT_TYPES.has(contentType)) return 'Content type not allowed.';
  return null;
}

function sanitizeFilename(name) {
  // Strip path separators and non-safe characters
  return name
    .replace(/[/\\]/g, '')
    .replace(/[^a-zA-Z0-9.\-_]/g, '_')
    .slice(0, 200);
}

function formatBytes(bytes) {
  if (bytes < 1024)         return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

// ---------------------------------------------------------------------------
// Route: GET /media — list all objects
// ---------------------------------------------------------------------------

async function listMedia(request, env) {
  const origin = request.headers.get('Origin') || '';
  const url    = new URL(request.url);
  const rawPrefix = url.searchParams.get('prefix') || '';
  // Only allow empty prefix (list all) or YYYY/MM[/] shaped prefixes
  if (rawPrefix && !/^\d{4}\/\d{2}(\/.*)?$/.test(rawPrefix)) {
    return jsonErr('Invalid prefix.', 400, origin, env);
  }
  const prefix = rawPrefix;
  const cursor = url.searchParams.get('cursor')  || undefined;

  const listed = await env.MEDIA_BUCKET.list({ prefix, cursor, limit: 200 });

  const objects = listed.objects.map(obj => ({
    key:          obj.key,
    size:         obj.size,
    sizeFormatted: formatBytes(obj.size),
    uploaded:     obj.uploaded,
    publicUrl:    `${env.R2_PUBLIC_URL}/${obj.key}`,
  }));

  return jsonOk({
    objects,
    truncated: listed.truncated,
    cursor:    listed.truncated ? listed.cursor : null,
  }, origin, env);
}

// ---------------------------------------------------------------------------
// Route: POST /media/upload — receive file via FormData, store via R2 binding
// ---------------------------------------------------------------------------

async function uploadMedia(request, env) {
  const origin = request.headers.get('Origin') || '';

  let formData;
  try { formData = await request.formData(); }
  catch { return jsonErr('Expected multipart/form-data.', 400, origin, env); }

  const file = formData.get('file');
  if (!file || typeof file.name !== 'string') {
    return jsonErr('Missing file field.', 400, origin, env);
  }

  const safeFilename = sanitizeFilename(file.name);
  const contentType  = file.type || 'application/octet-stream';
  const error = validateFile(safeFilename, contentType);
  if (error) return jsonErr(error, 400, origin, env);

  const MAX_BYTES = 1 * 1024 * 1024; // 1 MB
  if (file.size > MAX_BYTES) {
    return jsonErr('File exceeds the 1 MB size limit.', 413, origin, env);
  }

  // Prefix uploads with year/month to keep bucket organised
  const now   = new Date();
  const month = `${now.getFullYear()}/${String(now.getMonth() + 1).padStart(2, '0')}`;
  const key   = `${month}/${safeFilename}`;

  await env.MEDIA_BUCKET.put(key, await file.arrayBuffer(), {
    httpMetadata: { contentType },
  });

  return jsonOk({
    publicUrl: `${env.R2_PUBLIC_URL}/${key}`,
    key,
  }, origin, env);
}

// ---------------------------------------------------------------------------
// Route: DELETE /media/:key — delete an object (owner/moderator only)
// ---------------------------------------------------------------------------

async function deleteMedia(key, role, request, env) {
  const origin = request.headers.get('Origin') || '';

  if (!['owner', 'moderator'].includes(role)) {
    return jsonErr('Forbidden: only owner or moderator can delete media.', 403, origin, env);
  }

  if (!key || key.includes('..') || key.startsWith('/')) {
    return jsonErr('Invalid key.', 400, origin, env);
  }

  const existing = await env.MEDIA_BUCKET.head(key);
  if (!existing) return jsonErr('Object not found.', 404, origin, env);

  await env.MEDIA_BUCKET.delete(key);

  return jsonOk({ deleted: key }, origin, env);
}

// ---------------------------------------------------------------------------
// Main fetch handler
// ---------------------------------------------------------------------------

export default {
  async fetch(request, env) {
    const url    = new URL(request.url);
    const origin = request.headers.get('Origin') || '';
    const path   = url.pathname;

    // CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(origin, env) });
    }

    // All routes require auth
    const role = await requireAdmin(request, env);
    if (!role) return jsonErr('Unauthorized.', 401, origin, env);

    // POST /media/upload
    if (path === '/media/upload' && request.method === 'POST') {
      return uploadMedia(request, env);
    }

    // DELETE /media/:key
    const deleteMatch = path.match(/^\/media\/(.+)$/);
    if (deleteMatch && request.method === 'DELETE') {
      return deleteMedia(decodeURIComponent(deleteMatch[1]), role, request, env);
    }

    // GET /media
    if ((path === '/media' || path === '/media/') && request.method === 'GET') {
      return listMedia(request, env);
    }

    return jsonErr('Not found.', 404, origin, env);
  },
};
