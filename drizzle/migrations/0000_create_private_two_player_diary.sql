CREATE TABLE public.profiles (
  id uuid PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  display_name text NOT NULL UNIQUE CHECK (display_name IN ('T', 'V')),
  created_at timestamptz NOT NULL DEFAULT now()
);
GRANT SELECT ON public.profiles TO authenticated;
GRANT ALL ON public.profiles TO service_role;
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;

CREATE FUNCTION public.is_current_tvk_member()
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
  SELECT EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid())
$$;
REVOKE ALL ON FUNCTION public.is_current_tvk_member() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.is_current_tvk_member() TO authenticated;
CREATE POLICY "Assigned members can view member identities" ON public.profiles FOR SELECT TO authenticated USING (public.is_current_tvk_member());

CREATE FUNCTION public.assign_tvk_profile()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
  IF lower(NEW.email) = 't@tvk.invalid' THEN
    INSERT INTO public.profiles (id, display_name) VALUES (NEW.id, 'T') ON CONFLICT (id) DO NOTHING;
  ELSIF lower(NEW.email) = 'v@tvk.invalid' THEN
    INSERT INTO public.profiles (id, display_name) VALUES (NEW.id, 'V') ON CONFLICT (id) DO NOTHING;
  END IF;
  RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION public.assign_tvk_profile() FROM PUBLIC, anon, authenticated;
CREATE TRIGGER assign_tvk_profile_after_auth_insert AFTER INSERT ON auth.users FOR EACH ROW EXECUTE FUNCTION public.assign_tvk_profile();

CREATE TABLE public.diary_entries (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  title text NOT NULL DEFAULT '',
  content text NOT NULL DEFAULT '',
  entry_date date NOT NULL,
  author_id uuid NOT NULL REFERENCES public.profiles(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
GRANT SELECT, INSERT, DELETE ON public.diary_entries TO authenticated;
GRANT UPDATE (title, content, entry_date) ON public.diary_entries TO authenticated;
GRANT ALL ON public.diary_entries TO service_role;
ALTER TABLE public.diary_entries ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Assigned members can read shared diary entries" ON public.diary_entries FOR SELECT TO authenticated USING (public.is_current_tvk_member());
CREATE POLICY "Assigned members can create entries as themselves" ON public.diary_entries FOR INSERT TO authenticated WITH CHECK (public.is_current_tvk_member() AND author_id = auth.uid());
CREATE POLICY "Assigned members can edit shared diary entries" ON public.diary_entries FOR UPDATE TO authenticated USING (public.is_current_tvk_member()) WITH CHECK (public.is_current_tvk_member());
CREATE POLICY "Assigned members can delete shared diary entries" ON public.diary_entries FOR DELETE TO authenticated USING (public.is_current_tvk_member());
CREATE INDEX diary_entries_entry_date_created_at_idx ON public.diary_entries (entry_date, created_at);

CREATE TABLE public.sticky_notes (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  content text NOT NULL DEFAULT '',
  author_id uuid NOT NULL REFERENCES public.profiles(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
GRANT SELECT, INSERT, DELETE ON public.sticky_notes TO authenticated;
GRANT UPDATE (content) ON public.sticky_notes TO authenticated;
GRANT ALL ON public.sticky_notes TO service_role;
ALTER TABLE public.sticky_notes ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Assigned members can read shared sticky notes" ON public.sticky_notes FOR SELECT TO authenticated USING (public.is_current_tvk_member());
CREATE POLICY "Assigned members can create notes as themselves" ON public.sticky_notes FOR INSERT TO authenticated WITH CHECK (public.is_current_tvk_member() AND author_id = auth.uid());
CREATE POLICY "Assigned members can edit shared sticky notes" ON public.sticky_notes FOR UPDATE TO authenticated USING (public.is_current_tvk_member()) WITH CHECK (public.is_current_tvk_member());
CREATE POLICY "Assigned members can delete shared sticky notes" ON public.sticky_notes FOR DELETE TO authenticated USING (public.is_current_tvk_member());
CREATE INDEX sticky_notes_updated_at_idx ON public.sticky_notes (updated_at DESC);

CREATE FUNCTION public.set_updated_at()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION public.set_updated_at() FROM PUBLIC, anon, authenticated;
CREATE TRIGGER diary_entries_set_updated_at BEFORE UPDATE ON public.diary_entries FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();
CREATE TRIGGER sticky_notes_set_updated_at BEFORE UPDATE ON public.sticky_notes FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

ALTER PUBLICATION supabase_realtime ADD TABLE public.diary_entries;
ALTER PUBLICATION supabase_realtime ADD TABLE public.sticky_notes;