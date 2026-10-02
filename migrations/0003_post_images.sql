-- Adds persistent image URL support for posts. Run once against the existing D1 database.
ALTER TABLE posts ADD COLUMN image_url TEXT NOT NULL DEFAULT '';
