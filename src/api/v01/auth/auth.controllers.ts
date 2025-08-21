import z from "zod";
import { Request, Response } from "express";
import { Session, User } from "@supabase/supabase-js";

import { errorHandler } from "./auth.error";
import { supabase } from "../../../libs/db/db.supabase";
import { IUserProfileRoleType } from "../../../types/users";
import { loginSchema, registrationSchema } from "./auth.schemas";

import {
  loginAuthHelper,
  logoutAuthHelper,
  registerAuthHelper,
  verifyEmailAuthHelper,
  resetPasswordAuthHelper,
  forgotPasswordAuthHelper,
} from "./auth.helper";

//login controller
export const loginAuthController = async (req: Request, res: Response) => {
  try {
    const parsed = loginSchema.safeParse(req.body);

    if (!parsed.success) {
      if (process.env.NODE_ENV === "development") {
        console.error("[Validation Error]", parsed.error.issues); // Avoid .format()
      }

      return res.status(400).json({
        status: "failed",
        message: "Invalid input",
        errors: parsed.error.issues.map((issue) => ({
          path: issue.path.join("."),
          message: issue.message,
          code: issue.code,
        })),
      });
    }

    const { email, password, remember } = parsed.data;

    const result = await loginAuthHelper(email, password);
    const { user, session } = result as { user: User; session: Session };

    if (!session?.access_token || !session?.refresh_token) {
      return res.status(500).json({
        status: "error",
        message: "Token generation failed",
      });
    }

    const { data: roleData, error: roleError } = await supabase
      .from("iLocalUsers")
      .select("id, role")
      .eq("email", email)
      .single();

    if (roleError) throw roleError;

    const accessTokenMaxAge = remember ? 24 * 60 * 60 * 1000 : 15 * 60 * 1000; // 15 minutes or 1 days
    const refreshTokenMaxAge = remember
      ? 30 * 24 * 60 * 60 * 1000
      : 7 * 24 * 60 * 60 * 1000; // 7 days or 30 days

    res.cookie("accessToken", session.access_token, {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
      path: "/",
      maxAge: accessTokenMaxAge,
    });

    res.cookie("refreshToken", session.refresh_token, {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
      path: "/",
      maxAge: refreshTokenMaxAge,
    });

    const currentUser = {
      id: roleData?.id,
      email,
      role: (roleData?.role ?? "USER") as IUserProfileRoleType,
      created_at: user.created_at,
      updated_at: user.updated_at,
      isUserVerified: user.user_metadata?.isUserVerified ?? false,
    };

    return res.status(200).json({
      status: "success",
      message: "Login successful",
      data: { currentUser },
    });
  } catch (error: unknown) {
    errorHandler(error, req, res);
  }
};

//logout controller
export const logoutAuthController = async (req: Request, res: Response) => {
  try {
    const result = await logoutAuthHelper();

    return res.status(200).json({
      status: "success",
      message: "Logout successful",
      data: result,
    });
  } catch (error) {
    const message =
      error instanceof Error ? error.message : "Unknown internal error";

    console.error("Logout error:", error);

    return res.status(500).json({
      status: "error",
      message: "Internal server error",
      details: message,
    });
  }
};

//register controller
export const registerAuthController = async (req: Request, res: Response) => {
  try {
    const parsed = registrationSchema.safeParse(req.body);

    if (!parsed.success) {
      if (process.env.NODE_ENV === "development") {
        console.error("[Validation Error]", parsed.error.issues); // Avoid .format()
      }

      return res.status(400).json({
        status: "failed",
        message: "Invalid input",
        errors: parsed.error.issues.map((issue) => ({
          path: issue.path.join("."),
          message: issue.message,
          code: issue.code,
        })),
      });
    }

    const { email, fullname, password } = parsed.data;
    const result = await registerAuthHelper(email, password);
    const { user } = result as { user: User; session: Session };

    //new user information to be stored on database
    const newUser = {
      user_id: user.id,
      email: email,
      fullname: fullname,
      role: "USER" as IUserProfileRoleType,
      created_at: user.created_at,
      updated_at: user.updated_at,
    };

    const { error: insertError } = await supabase
      .from("iLocalUsers")
      .insert([newUser])
      .single();

    if (insertError) {
      throw insertError;
    }

    return res.status(201).json({
      status: "success",
      message: "Registration successful",
      data: newUser,
    });
  } catch (error) {
    return errorHandler(error, req, res);
  }
};

export const verifyEmailAuthController = async (
  req: Request,
  res: Response
) => {
  try {
    const result = await verifyEmailAuthHelper();

    return res.status(200).json({
      status: "success",
      message: "Email verification successful",
      data: result,
    });
  } catch (error) {
    const message =
      error instanceof Error ? error.message : "Unknown internal error";

    console.error("Verify email error:", error);

    return res.status(500).json({
      status: "error",
      message: "Internal server error",
      details: message,
    });
  }
};

export const resetPasswordAuthController = async (
  req: Request,
  res: Response
) => {
  try {
    const { newPassword } = req.body as { newPassword: string };

    if (!newPassword) {
      return res.status(400).json({
        status: "fail",
        message: "New password is required",
      });
    }

    const result = await resetPasswordAuthHelper(newPassword);

    return res.status(200).json({
      status: "success",
      message: "Password reset successful",
      data: result,
    });
  } catch (error) {
    const message =
      error instanceof Error ? error.message : "Unknown internal error";

    console.error("Reset password error:", error);

    return res.status(500).json({
      status: "error",
      message: "Internal server error",
      details: message,
    });
  }
};

export const forgotPasswordAuthController = async (
  req: Request,
  res: Response
) => {
  try {
    const { email } = req.body as { email: string };

    if (!email) {
      return res.status(400).json({
        status: "fail",
        message: "Email is required",
      });
    }

    const result = await forgotPasswordAuthHelper(email);

    return res.status(200).json({
      status: "success",
      message: "Password recovery email sent",
      data: result,
    });
  } catch (error) {
    const message =
      error instanceof Error ? error.message : "Unknown internal error";

    console.error("Forgot password error:", error);

    return res.status(500).json({
      status: "error",
      message: "Internal server error",
      details: message,
    });
  }
};
