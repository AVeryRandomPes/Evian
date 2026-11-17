-- Twofold encrypted attachments: raise the private bucket limit to 25 MiB per file.
-- Files remain client-side encrypted and are uploaded as application/octet-stream.
DO $$
DECLARE
  updated_count integer;
BEGIN
  UPDATE storage.buckets
  SET file_size_limit = 26214400,
      allowed_mime_types = NULL
  WHERE id = 'twofold-media';

  GET DIAGNOSTICS updated_count = ROW_COUNT;
  IF updated_count = 0 THEN
    RAISE EXCEPTION 'Storage bucket twofold-media was not found. Create the existing Twofold media bucket first.';
  END IF;
END $$;
