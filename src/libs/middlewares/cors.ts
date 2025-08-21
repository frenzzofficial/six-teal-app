import cors from "cors";
import { allowedOrigins } from "../configs/config.domain";

const isDev = process.env.NODE_ENV === "development";

const corsOptions: cors.CorsOptions = {
  origin: function (
    origin: string | undefined,
    callback: (err: Error | null, allow?: boolean) => void
  ) {
    if (!origin) {
      if (isDev) console.log("[CORS] No origin, allowing request");
      return callback(null, true); // Allow curl, mobile apps, etc.
    }

    if (allowedOrigins.includes(origin)) {
      if (isDev) console.log(`[CORS] Allowed origin: ${origin}`);
      return callback(null, true);
    }

    if (isDev) {
      console.warn(`[CORS] Blocked origin: ${origin}`);
    }

    return callback(new Error("Not allowed by CORS"), false);
  },

  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With"],
  exposedHeaders: ["Set-Cookie"],
};

export const corsMiddleware = cors(corsOptions);
