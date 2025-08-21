import { z } from "zod";
import { allowedMailDomains } from "../../libs/configs/config.domain";

// 🧩 Shared schema messages
export const schemaMessages = {
  emailInvalid: "Invalid email format",
  emailRequired: "Email is required",
  emailDomain: "Email must be from valid domains like gmail.com or hotmail.com",
  nameTooShort: "Name must be at least 5 characters",
  passwordTooShort: "Password must be at least 8 characters long",
  passwordUpper: "Must contain at least one uppercase letter",
  passwordLower: "Must contain at least one lowercase letter",
  passwordNumber: "Must contain at least one number",
  passwordSpecial: "Must contain at least one special character",
  passwordNoSpaces: "Password must not contain spaces",
  passwordMismatch: "Passwords do not match",
  termsRequired: "You must accept the terms and conditions to proceed.",
  topicRequired: "Topic is required",
  messageRequired: "Message is required",
};

// 🔐 Full name rules
export const fullnameRules = z
  .string()
  .min(6, schemaMessages.nameTooShort)
  .describe("Full name");

// 🔐 Email rules
export const emailRules = z
  .email(schemaMessages.emailInvalid)
  .trim()
  .min(6, schemaMessages.emailRequired)
  .refine(
    (email) => {
      const domain = email.toLowerCase().split("@")[1];
      return allowedMailDomains.includes(domain);
    },
    {
      message: schemaMessages.emailDomain,
    }
  )
  .describe("Email");

// 🔐 Shared password rules
export const passwordRules = z
  .string()
  .trim()
  .min(8, schemaMessages.passwordTooShort)
  .regex(/[A-Z]/, schemaMessages.passwordUpper)
  .regex(/[a-z]/, schemaMessages.passwordLower)
  .regex(/[0-9]/, schemaMessages.passwordNumber)
  .regex(/[^A-Za-z0-9]/, schemaMessages.passwordSpecial)
  .refine((val) => !/\s/.test(val), {
    message: schemaMessages.passwordNoSpaces,
  })
  .describe("Secure password with mixed characters");

// 🔐 Terms and conditions rules
export const termsAcceptedRules = z.boolean().refine((val) => val === true, {
  message: schemaMessages.termsRequired,
});
