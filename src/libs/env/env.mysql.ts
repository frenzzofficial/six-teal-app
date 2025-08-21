import { config } from "dotenv";
import { z } from "zod";

// ✅ Load environment variables from .env file
config(); // Must be called before accessing process.env

// ✅ Define schema with defaults and transformations
const envConfigSchema = z.object({
  MYSQL_HOST: z.string().default("localhost"),
  MYSQL_PORT: z
    .string()
    .default("3306")
    .transform((val) => Number(val)),
  MYSQL_USER: z.string().default("root"),
  MYSQL_PASSWORD: z.string().default("root"),
  MYSQL_DATABASE: z.string().default("test"),
  MYSQL_SYNC: z
    .string()
    .default("0")
    .transform((val) => Number(val)),
});

// ✅ Validate process.env safely
const parsed = envConfigSchema.safeParse(process.env);

if (!parsed.success) {
  throw new Error(
    `❌ Invalid mysql environment variables:\n${parsed.error.issues
      .map((i) => `• ${i.path.join(".")}: ${i.message}`)
      .join("\n")}`
  );
}

// ✅ Export validated config
export const envMysqlConfig = Object.freeze(parsed.data);

// ✅ Optional: Export type (for type-safe config)
export type EnvMysqlConfig = z.infer<typeof envConfigSchema>;
