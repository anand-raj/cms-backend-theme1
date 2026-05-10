CREATE TABLE IF NOT EXISTS admins (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  github_login TEXT    NOT NULL UNIQUE,
  role         TEXT    NOT NULL DEFAULT 'moderator', -- owner | moderator | section_editor
  section      TEXT,            -- state name; required when role = section_editor, NULL otherwise
  added_at     TEXT    NOT NULL
);
-- Migration for existing databases:
-- ALTER TABLE admins ADD COLUMN section TEXT;
