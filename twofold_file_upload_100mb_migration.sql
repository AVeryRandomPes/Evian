-- Twofold encrypted attachments: raise the private media bucket limit to 100 MiB.
-- The browser encrypts every attachment before it reaches Supabase Storage.
DO $$
DECLARE
  updated_count integer;
BEGIN
  UPDATE storage.buckets
  SET file_size_limit = 104857600,
      allowed_mime_types = NULL
  WHERE id = 'twofold-media';

  GET DIAGNOSTICS updated_count = ROW_COUNT;
  IF updated_count = 0 THEN
    RAISE EXCEPTION 'Storage bucket twofold-media was not found. Create the existing Twofold media bucket first.';
  END IF;
END $$;
