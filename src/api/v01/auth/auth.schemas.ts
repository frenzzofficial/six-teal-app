import { z } from "zod";
import {
  emailRules,
  fullnameRules,
  passwordRules,
  schemaMessages,
  termsAcceptedRules,
} from "../../../libs/configs/config.schema";

// 🧾 Registration schema
export const registrationSchema = z
  .object({
    fullname: fullnameRules,
    email: emailRules,
    password: passwordRules,
    terms: termsAcceptedRules,
  })
  .describe("Registration form");

// 🔐 Login schema
export const loginSchema = z
  .object({
    email: emailRules,
    password: passwordRules,
    remember: z.boolean().optional(),
  })
  .describe("Login form");

// 📬 Contact schema
export const contactSchema = z
  .object({
    fullname: fullnameRules,
    email: emailRules,
    topic: z.string().trim().min(5, schemaMessages.topicRequired),
    message: z.string().trim().min(5, schemaMessages.messageRequired),
    newsletter: z.boolean().optional(),
  })
  .describe("Contact form");
