-- ==========================================
-- TWOFOLD GLOBAL PRESENCE AUTHORIZATION
-- ==========================================
-- Allows approved, authenticated chat members to read and publish presence
-- only on the shared global online-status channel.

DROP POLICY IF EXISTS "twofold approved members read global presence" ON realtime.messages;
CREATE POLICY "twofold approved members read global presence"
ON realtime.messages
FOR SELECT
TO authenticated
USING (
  realtime.topic() = 'twofold-presence-global'
  AND EXISTS (
    SELECT 1
    FROM public.chat_members AS cm
    WHERE cm.user_id = (SELECT auth.uid())
  )
);

DROP POLICY IF EXISTS "twofold approved members publish global presence" ON realtime.messages;
CREATE POLICY "twofold approved members publish global presence"
ON realtime.messages
FOR INSERT
TO authenticated
WITH CHECK (
  realtime.topic() = 'twofold-presence-global'
  AND EXISTS (
    SELECT 1
    FROM public.chat_members AS cm
    WHERE cm.user_id = (SELECT auth.uid())
  )
);
