-- Wisal public portal: approved public records, admin-only changes, public attachments.
create table if not exists public.app_admins (
  user_id uuid primary key references auth.users(id) on delete cascade,
  created_at timestamptz not null default now()
);
alter table public.app_admins enable row level security;
grant select on public.app_admins to authenticated;
create policy "Admins can view their own membership" on public.app_admins
  for select to authenticated using (user_id = (select auth.uid()));

create or replace function public.is_wisal_admin()
returns boolean language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.app_admins a where a.user_id = (select auth.uid()));
$$;
revoke all on function public.is_wisal_admin() from public;
grant execute on function public.is_wisal_admin() to anon, authenticated;

create table if not exists public.portal_records (
  id uuid primary key default gen_random_uuid(),
  section text not null check (section in ('positive-behavior','announcements','student-blog','parent-blog','recognitions','success-stories','events-magazine','volunteer-work','student-board','parent-board')),
  title text not null,
  category text,
  details jsonb not null default '{}'::jsonb,
  attachment_path text,
  is_published boolean not null default true,
  created_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index if not exists portal_records_section_published_idx on public.portal_records(section,is_published,created_at desc);
alter table public.portal_records enable row level security;
grant select on public.portal_records to anon, authenticated;
grant insert, update, delete on public.portal_records to authenticated;
create policy "Public can view published portal records" on public.portal_records
  for select to anon, authenticated using (is_published or (select public.is_wisal_admin()));
create policy "Admins can create portal records" on public.portal_records
  for insert to authenticated with check ((select public.is_wisal_admin()));
create policy "Admins can update portal records" on public.portal_records
  for update to authenticated using ((select public.is_wisal_admin())) with check ((select public.is_wisal_admin()));
create policy "Admins can delete portal records" on public.portal_records
  for delete to authenticated using ((select public.is_wisal_admin()));

create or replace function public.set_portal_record_updated_at()
returns trigger language plpgsql set search_path = '' as $$
begin new.updated_at = now(); return new; end;
$$;
create trigger portal_records_updated_at before update on public.portal_records
  for each row execute function public.set_portal_record_updated_at();

insert into storage.buckets(id,name,public,file_size_limit,allowed_mime_types)
values('wisal-files','wisal-files',true,15728640,array['image/jpeg','image/png','image/webp','application/pdf','application/msword','application/vnd.openxmlformats-officedocument.wordprocessingml.document','application/vnd.ms-excel','application/vnd.openxmlformats-officedocument.spreadsheetml.sheet','application/vnd.ms-powerpoint','application/vnd.openxmlformats-officedocument.presentationml.presentation','text/plain'])
on conflict(id) do nothing;
create policy "Public can view Wisal attachments" on storage.objects
  for select to anon, authenticated using (bucket_id='wisal-files');
create policy "Admins can upload Wisal attachments" on storage.objects
  for insert to authenticated with check (bucket_id='wisal-files' and (select public.is_wisal_admin()));
create policy "Admins can update Wisal attachments" on storage.objects
  for update to authenticated using (bucket_id='wisal-files' and (select public.is_wisal_admin()))
  with check (bucket_id='wisal-files' and (select public.is_wisal_admin()));
create policy "Admins can delete Wisal attachments" on storage.objects
  for delete to authenticated using (bucket_id='wisal-files' and (select public.is_wisal_admin()));
