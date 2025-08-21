import { createClient } from "@supabase/supabase-js";
import { envSupabaseConfig } from "../env/env.supabase";

const supabaseUrl = envSupabaseConfig.SUPABASE_URL;
const supabaseKey = envSupabaseConfig.SUPABASE_ANON_KEY;

export const supabase = createClient(supabaseUrl, supabaseKey);
