-- CMS database schema — admins table
-- Used by: cloudflare-membership-worker (admin CRUD), cloudflare-media-worker (auth)
--
-- Apply with:
--   NODE_TLS_REJECT_UNAUTHORIZED=0 npx wrangler d1 execute cms --remote --file=schema.sql

-- ── Admins ─────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS admins (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  github_login TEXT    NOT NULL UNIQUE,
  role         TEXT    NOT NULL DEFAULT 'moderator', -- owner | moderator | section_editor
  section      TEXT,                                 -- state/section for section_editor role
  added_at     TEXT    NOT NULL
);
