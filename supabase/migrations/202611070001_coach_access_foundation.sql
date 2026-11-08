-- AFFA Academy Desk: coach access foundation
-- Additive migration. Does not modify or delete existing academy_documents records
-- or existing admin/member policies.
--
-- IMPORTANT: Apply together with the matching app update. The current app still
-- uses date-wide JSON attendance documents; coaches must not be enabled until
-- it has been updated to use academy_attendance below.

alter table public.academy_members
  add column if not exists coach_id text;

create unique index if not exists academy_members_coach_id_unique
  on public.academy_members (coach_id)
  where coach_id is not null and role = 'coach';

create table if not exists public.academy_attendance (
  attendance_date date not null,
  student_id text not null,
  status text not null check (status in ('P', 'A', 'L')),
  updated_by uuid not null references auth.users(id) on delete restrict,
  updated_at timestamptz not null default now(),
  primary key (attendance_date, student_id)
);

alter table public.academy_attendance enable row level security;
grant select, insert, update on public.academy_attendance to authenticated;

-- Admins retain full control of normalized attendance.
drop policy if exists "Admins can manage normalized attendance" on public.academy_attendance;
create policy "Admins can manage normalized attendance"
on public.academy_attendance
for all to authenticated
using (
  exists (
    select 1 from public.academy_members m
    where m.user_id = (select auth.uid()) and m.role = 'admin'
  )
)
with check (
  exists (
    select 1 from public.academy_members m
    where m.user_id = (select auth.uid()) and m.role = 'admin'
  )
);

-- SECURITY DEFINER helper avoids recursive RLS when checking a student's batch.
-- It returns only a boolean and never exposes unrelated academy_documents rows.
create or replace function public.aff_coach_can_view_document(
  p_collection text,
  p_id text,
  p_data jsonb
)
returns boolean
language sql
stable
security definer
set search_path = public, auth, pg_temp
as $$
  select exists (
    select 1
    from public.academy_members m
    where m.user_id = (select auth.uid())
      and m.role = 'coach'
      and m.coach_id is not null
      and (
        (p_collection = 'batches' and coalesce(p_data->'coachIds', '[]'::jsonb) ? m.coach_id)
        or (p_collection = 'coaches' and p_id = m.coach_id)
        or (
          p_collection = 'students'
          and exists (
            select 1
            from public.academy_documents b
            where b.collection = 'batches'
              and b.id = p_data->>'batchId'
              and coalesce(b.data->'coachIds', '[]'::jsonb) ? m.coach_id
          )
        )
      )
  );
$$;

revoke all on function public.aff_coach_can_view_document(text,text,jsonb) from public;
grant execute on function public.aff_coach_can_view_document(text,text,jsonb) to authenticated;

drop policy if exists "Coaches can view assigned batches and students" on public.academy_documents;
create policy "Coaches can view assigned batches and students"
on public.academy_documents
for select to authenticated
using (public.aff_coach_can_view_document(collection, id, data));

-- A coach can read attendance only for students currently assigned to one of
-- their batches. This is a separate normalized table so row-level security
-- can protect individual students rather than a whole date-wide JSON document.
drop policy if exists "Coaches can view attendance for assigned students" on public.academy_attendance;
create policy "Coaches can view attendance for assigned students"
on public.academy_attendance
for select to authenticated
using (
  exists (
    select 1
    from public.academy_members m
    join public.academy_documents s
      on s.collection = 'students'
     and s.id = academy_attendance.student_id
    join public.academy_documents b
      on b.collection = 'batches'
     and b.id = s.data->>'batchId'
    where m.user_id = (select auth.uid())
      and m.role = 'coach'
      and m.coach_id is not null
      and coalesce(b.data->'coachIds', '[]'::jsonb) ? m.coach_id
  )
);

drop policy if exists "Coaches can mark attendance for assigned students" on public.academy_attendance;
create policy "Coaches can mark attendance for assigned students"
on public.academy_attendance
for insert to authenticated
with check (
  updated_by = (select auth.uid())
  and exists (
    select 1
    from public.academy_members m
    join public.academy_documents s
      on s.collection = 'students'
     and s.id = academy_attendance.student_id
    join public.academy_documents b
      on b.collection = 'batches'
     and b.id = s.data->>'batchId'
    where m.user_id = (select auth.uid())
      and m.role = 'coach'
      and m.coach_id is not null
      and coalesce(b.data->'coachIds', '[]'::jsonb) ? m.coach_id
  )
);

drop policy if exists "Coaches can update attendance for assigned students" on public.academy_attendance;
create policy "Coaches can update attendance for assigned students"
on public.academy_attendance
for update to authenticated
using (
  exists (
    select 1
    from public.academy_members m
    join public.academy_documents s
      on s.collection = 'students'
     and s.id = academy_attendance.student_id
    join public.academy_documents b
      on b.collection = 'batches'
     and b.id = s.data->>'batchId'
    where m.user_id = (select auth.uid())
      and m.role = 'coach'
      and m.coach_id is not null
      and coalesce(b.data->'coachIds', '[]'::jsonb) ? m.coach_id
  )
)
with check (
  updated_by = (select auth.uid())
  and exists (
    select 1
    from public.academy_members m
    join public.academy_documents s
      on s.collection = 'students'
     and s.id = academy_attendance.student_id
    join public.academy_documents b
      on b.collection = 'batches'
     and b.id = s.data->>'batchId'
    where m.user_id = (select auth.uid())
      and m.role = 'coach'
      and m.coach_id is not null
      and coalesce(b.data->'coachIds', '[]'::jsonb) ? m.coach_id
  )
);

-- No coach INSERT/UPDATE/DELETE policy is added to academy_documents.
-- Existing date-wide attendance JSON, fees, payments, plans, settings and
-- coach-management writes therefore remain admin-only.
