-- Twofold encrypted attachments: raise the private bucket limit to 25 MiB per file.
-- Files remain client-side encrypted and are uploaded as application/octet-stream.
UPDATE storage.buckets
SET file_size_limit = 26214400,
    allowed_mime_types = NULL
WHERE id = 'twofold-media';

DO $$
BEGIN
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Storage bucket twofold-media was not found. Create the existing Twofold media bucket first.';
  END IF;
END $$;
