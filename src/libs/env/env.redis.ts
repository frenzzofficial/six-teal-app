import { config } from "dotenv";
import { z } from "zod";

// ✅ Load environment variables from .env file
config(); // Must be called before accessing process.env

// ✅ Define schema with defaults and transformations
const envConfigSchema = z.object({
  REDIS_URL: z.url().trim().default("redis-url"),
  REDIS_TOKEN: z.string().default("redis-token"),
});

// ✅ Validate process.env safely
const parsed = envConfigSchema.safeParse(process.env);

if (!parsed.success) {
  throw new Error(
    `❌ Invalid redis environment variables:\n${parsed.error.issues
      .map((i) => `• ${i.path.join(".")}: ${i.message}`)
      .join("\n")}`
  );
}

// ✅ Export validated config
export const envRedisConfig = Object.freeze(parsed.data);

// ✅ Optional: Export type (for type-safe config)
export type EnvRedisConfig = z.infer<typeof envConfigSchema>;
