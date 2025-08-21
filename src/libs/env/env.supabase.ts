import { config } from "dotenv";
import { z } from "zod";

// ✅ Load environment variables from .env file
config(); // Must be called before accessing process.env

// ✅ Define schema with defaults and transformations
const envConfigSchema = z.object({
  SUPABASE_URL: z.url().trim().default("http://localhost:54321"),
  SUPABASE_ANON_KEY: z.string().default("anon-key"),
});

// ✅ Validate process.env safely
const parsed = envConfigSchema.safeParse(process.env);

if (!parsed.success) {
  throw new Error(
    `❌ Invalid supabase environment variables:\n${parsed.error.issues
      .map((i) => `• ${i.path.join(".")}: ${i.message}`)
      .join("\n")}`
  );
}

// ✅ Export validated config
export const envSupabaseConfig = Object.freeze(parsed.data);

// ✅ Optional: Export type (for type-safe config)
export type EnvSupabaseConfig = z.infer<typeof envConfigSchema>;
