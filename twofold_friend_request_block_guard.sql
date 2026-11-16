-- Twofold friend-request blocking enforcement
-- Rejects request creation and acceptance whenever either participant has blocked the other.

begin;

create or replace function public.twofold_guard_friend_request_blocks()
returns trigger
language plpgsql
security definer
set search_path = ''
set row_security = 'off'
as $$
begin
  if new.sender_id is null or new.receiver_id is null or new.sender_id = new.receiver_id then
    raise exception 'Invalid friend request.';
  end if;

  if public.twofold_is_blocked_between(new.sender_id, new.receiver_id) then
    raise exception 'Friend requests are unavailable because one of these users has blocked the other.';
  end if;

  return new;
end;
$$;

drop trigger if exists twofold_guard_friend_request_blocks on public.friend_requests;
create trigger twofold_guard_friend_request_blocks
before insert or update of sender_id, receiver_id, status
on public.friend_requests
for each row
execute function public.twofold_guard_friend_request_blocks();

revoke all on function public.twofold_guard_friend_request_blocks() from public, anon, authenticated;

commit;
