import { Request, Response } from "express";
import { AuthError } from "@supabase/supabase-js";

export const errorHandler = async (
  error: unknown,
  req: Request,
  res: Response
) => {
  const errorObj = error as AuthError;
  const message = errorObj.message
    ? errorObj.message
    : "Unknown internal error";
  return res.status(500).json({
    status: "error",
    message: "Internal server error",
    details: message,
  });
};
