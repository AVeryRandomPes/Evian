-- Twofold blocking, visibility, and conversation menu support
-- Safe to run after the existing Twofold schema. Does not delete user data.

begin;

-- A viewer can see a conversation only while they are a member, it is not
-- hidden for them, and no other participant has blocked them (for DMs).
create or replace function public.twofold_can_view_conversation(
  check_conversation_id uuid,
  check_user_id uuid
) returns boolean
language sql
stable
security definer
set search_path = ''
set row_security = 'off'
as $$
  select exists (
    select 1
    from public.conversation_members cm
    join public.conversations c on c.id = cm.conversation_id
    where cm.conversation_id = check_conversation_id
      and cm.user_id = check_user_id
      and not exists (
        select 1
        from public.conversation_user_settings s
        where s.conversation_id = check_conversation_id
          and s.user_id = check_user_id
          and s.hidden_at is not null
      )
      and (
        c.type <> 'direct'
        or not exists (
          select 1
          from public.conversation_members other_member
          where other_member.conversation_id = check_conversation_id
            and other_member.user_id <> check_user_id
            and public.twofold_is_blocked_between(check_user_id, other_member.user_id)
        )
      )
  );
$$;

-- Group messages from a blocked sender remain available to other group
-- members, but are filtered from the blocker. DMs are hidden both ways.
create or replace function public.twofold_can_view_message(
  message_conversation_id uuid,
  message_sender_id uuid,
  viewer_id uuid
) returns boolean
language sql
stable
security definer
set search_path = ''
set row_security = 'off'
as $$
  select
    public.twofold_can_view_conversation(message_conversation_id, viewer_id)
    and exists (
      select 1
      from public.conversation_members cm
      where cm.conversation_id = message_conversation_id
        and cm.user_id = viewer_id
    )
    and (
      message_sender_id = viewer_id
      or not exists (
        select 1
        from public.blocked_users b
        where b.blocker_id = viewer_id
          and b.blocked_id = message_sender_id
      )
    );
$$;

-- Replace duplicate/old SELECT policies with one policy per table.
drop policy if exists "Users can view their conversations" on public.conversations;
create policy "Twofold members see visible conversations"
on public.conversations for select to authenticated
using (public.twofold_can_view_conversation(id, auth.uid()));

drop policy if exists "Users can read conversation messages" on public.messages;
drop policy if exists "Twofold conversation members can read messages" on public.messages;
create policy "Twofold members see permitted messages"
on public.messages for select to authenticated
using (public.twofold_can_view_message(conversation_id, sender_id, auth.uid()));

-- Keep a single INSERT policy. The trigger below performs the block check.
drop policy if exists "Users can send conversation messages" on public.messages;
drop policy if exists "Twofold conversation members can send messages" on public.messages;
create policy "Twofold members can send messages"
on public.messages for insert to authenticated
with check (
  sender_id = auth.uid()
  and public.twofold_is_conversation_member(conversation_id, auth.uid())
);

-- Blocking prevents direct messages, but does not stop a blocked member from
-- posting in a shared group where other members may still read their message.
create or replace function public.twofold_check_message_block()
returns trigger
language plpgsql
security definer
set search_path = ''
set row_security = 'off'
as $$
declare
  conversation_kind text;
  blocked_count integer;
begin
  select c.type into conversation_kind
  from public.conversations c
  where c.id = new.conversation_id;

  if conversation_kind = 'direct' then
    select count(*) into blocked_count
    from public.conversation_members cm
    where cm.conversation_id = new.conversation_id
      and cm.user_id <> new.sender_id
      and public.twofold_is_blocked_between(new.sender_id, cm.user_id);

    if blocked_count > 0 then
      raise exception 'This direct message is unavailable.';
    end if;
  end if;
  return new;
end;
$$;

-- Prevent creating/retrieving a DM if either participant has blocked the other.
create or replace function public.twofold_get_or_create_dm(other_user uuid)
returns uuid
language plpgsql
security definer
set search_path = ''
set row_security = 'off'
as $$
declare
  result_id uuid;
  pair_key text;
begin
  if auth.uid() is null or other_user is null or other_user = auth.uid() then
    raise exception 'Invalid DM participant';
  end if;

  if not exists (select 1 from public.chat_members where user_id = auth.uid())
     or not exists (select 1 from public.chat_members where user_id = other_user) then
    raise exception 'Both users must be approved Twofold members';
  end if;

  if public.twofold_is_blocked_between(auth.uid(), other_user) then
    raise exception 'This direct message is unavailable.';
  end if;

  pair_key := least(auth.uid()::text, other_user::text) || ':' ||
              greatest(auth.uid()::text, other_user::text);

  insert into public.conversations (type, created_by, dm_key)
  values ('direct', auth.uid(), pair_key)
  on conflict (dm_key) do update set dm_key = excluded.dm_key
  returning id into result_id;

  insert into public.conversation_members (conversation_id, user_id)
  values (result_id, auth.uid()), (result_id, other_user)
  on conflict do nothing;

  return result_id;
end;
$$;

-- A blocked user cannot send friend requests to the blocker (or vice versa).
-- The existing twofold_send_friend_request already performs this check.
-- Revoke public execution of the internal visibility helpers.
revoke all on function public.twofold_can_view_conversation(uuid,uuid) from public;
revoke all on function public.twofold_can_view_message(uuid,uuid,uuid) from public;
grant execute on function public.twofold_can_view_conversation(uuid,uuid) to authenticated;
grant execute on function public.twofold_can_view_message(uuid,uuid,uuid) to authenticated;
grant execute on function public.twofold_block_user(uuid) to authenticated;
grant execute on function public.twofold_unblock_user(uuid) to authenticated;
grant execute on function public.twofold_remove_friend(uuid) to authenticated;
grant execute on function public.twofold_send_friend_request(text) to authenticated;
grant execute on function public.twofold_get_or_create_dm(uuid) to authenticated;

commit;
