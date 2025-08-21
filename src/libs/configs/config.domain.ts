import { envFrontendConfig } from "../env/env.frontend";

export const allowedMailDomains = ["gmail.com", "hotmail.com", "outlook.com"];

export const allowedOriginsList = [envFrontendConfig.APP_FRONTEND].filter(
  Boolean
);

// Load allowed origins from env or fallback
export const allowedOrigins =
  envFrontendConfig.APP_FRONTEND?.split(",").map((o) => o.trim()) ||
  allowedOriginsList;
