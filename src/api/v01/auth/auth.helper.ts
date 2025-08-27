import { supabase } from "../../../libs/db/db.supabase";
import { AuthResponse, User, UserResponse } from "@supabase/supabase-js";

// Custom error type
interface AuthError {
  message: string;
  status?: number;
}

interface LogoutResult {
  success: boolean;
  message: string;
}

// Controller return type
type LoginResult = AuthResponse["data"] | null;
type RegisterResult = AuthResponse["data"] | null;
interface VerificationResult {
  verified: boolean;
  email?: string;
}
interface ResetPasswordResult {
  message: string;
}
interface ForgotPasswordResult {
  message: string;
}

/**
 * Attempts to log in a user via Supabase.
 * @param email - User's email
 * @param password - User's password
 * @returns Supabase user session on success
 * @throws AuthError with descriptive message
 */
export const loginAuthHelper = async (
  email: string,
  password: string
): Promise<LoginResult> => {
  if (!email || !password) {
    throw {
      message: "Email and password are required for login.",
      status: 400,
    } satisfies AuthError;
  }

  try {
    const { data, error } = await supabase.auth.signInWithPassword({
      email,
      password,
    });

    if (error) {
      throw {
        message:
          error.message || "Login failed. Please check your credentials.",
        status: error.status || 401,
      } satisfies AuthError;
    }

    if (!data?.session) {
      throw {
        message: "No active session returned. Login may have failed silently.",
        status: 500,
      } satisfies AuthError;
    }

    return data;
  } catch (err: unknown) {
    const fallback = err as AuthError;
    throw {
      message: fallback?.message || "Unexpected error during login.",
      status: fallback?.status || 500,
    };
  }
};

/**
 * Logs out the current user session.
 * @returns success status on successful logout
 * @throws AuthError with helpful message
 */
export const logoutAuthHelper = async (): Promise<LogoutResult> => {
  try {
    const { error } = await supabase.auth.signOut();

    if (error) {
      throw {
        message: error.message || "Logout failed due to Supabase error.",
        status: error.status || 500,
      } satisfies AuthError;
    }

    return { success: true, message: "user logged out successfully" };
  } catch (err: unknown) {
    const fallback = err as AuthError;
    throw {
      message: fallback?.message || "Unexpected error during logout.",
      status: fallback?.status || 500,
    };
  }
};

/**
 * Registers a new user with Supabase.
 * @param email - New user's email
 * @param fullname - New fullname
 * @param password - New user's password
 * @returns User session on successful signup
 * @throws AuthError with descriptive feedback
 */
export const registerAuthHelper = async (
  email: string,
  password: string
): Promise<RegisterResult> => {
  if (!email || !password) {
    throw {
      message: "Email and password are required to register.",
      status: 400,
    } satisfies AuthError;
  }

  try {
    const { data, error } = await supabase.auth.signUp({ email, password });

    if (error) {
      throw {
        message: error.message || "Registration failed. Try a different email.",
        status: error.status || 409,
      } satisfies AuthError;
    }

    if (!data?.user) {
      throw {
        message:
          "No user object returned. Something went wrong during registration.",
        status: 500,
      } satisfies AuthError;
    }

    return data;
  } catch (err: unknown) {
    const fallback = err as AuthError;
    throw {
      message: fallback?.message || "Unexpected error during registration.",
      status: fallback?.status || 500,
    };
  }
};

/**
 * Checks if the current user has verified their email.
 * @returns { verified: boolean, email?: string }
 * @throws AuthError with structured message
 */
export const verifyEmailAuthHelper = async (): Promise<VerificationResult> => {
  try {
    const {
      data: { user },
      error,
    }: UserResponse = await supabase.auth.getUser();

    if (error) {
      throw {
        message: error.message || "Failed to retrieve user data.",
        status: error.status || 401,
      } satisfies AuthError;
    }

    if (!user || !user.email) {
      throw {
        message: "User is not logged in or email is unavailable.",
        status: 403,
      } satisfies AuthError;
    }

    return {
      verified: Boolean(user.email_confirmed_at),
      email: user.email,
    };
  } catch (err: unknown) {
    const fallback = err as AuthError;
    throw {
      message:
        fallback?.message || "Unexpected error during email verification.",
      status: fallback?.status || 500,
    };
  }
};
/**
 * Resets user password via accessToken-based recovery flow.
 * Must be called in client-side context where recovery token is already set.
 * @param newPassword - New password to set
 * @returns Confirmation message
 * @throws AuthError if reset fails
 */
export const resetPasswordAuthHelper = async (
  newPassword: string
): Promise<ResetPasswordResult> => {
  if (!newPassword) {
    throw {
      message: "New password is required.",
      status: 400,
    } satisfies AuthError;
  }

  try {
    const { error } = await supabase.auth.updateUser({ password: newPassword });

    if (error) {
      throw {
        message: error.message || "Password reset failed.",
        status: error.status || 401,
      } satisfies AuthError;
    }

    return { message: "Password reset successful." };
  } catch (err: unknown) {
    const fallback = err as AuthError;
    throw {
      message: fallback.message || "Unexpected error during password reset.",
      status: fallback.status || 500,
    };
  }
};

/**
 * Sends a password recovery email to the provided address.
 * @param email - User's email address
 * @returns Success message if email was dispatched
 * @throws AuthError if recovery fails
 */
export const forgotPasswordAuthHelper = async (
  email: string
): Promise<ForgotPasswordResult> => {
  if (!email) {
    throw {
      message: "Email is required to initiate password recovery.",
      status: 400,
    } satisfies AuthError;
  }

  try {
    const { error } = await supabase.auth.resetPasswordForEmail(email);

    if (error) {
      throw {
        message: error.message || "Failed to send recovery email.",
        status: error.status || 422,
      } satisfies AuthError;
    }

    return { message: "Recovery email sent successfully." };
  } catch (err: unknown) {
    const fallback = err as AuthError;
    throw {
      message: fallback.message || "Unexpected error during password recovery.",
      status: fallback.status || 500,
    };
  }
};

export const getUserProfileHelper = async () => {
  try {
    const { data, error } = await supabase.auth.getUser();

    if (error) {
      console.error("[Supabase Auth Error]", error.message);
      throw {
        message: error.message || "Failed to verify access token.",
        status: error.status || 401,
      } satisfies AuthError;
    }

    if (!data?.user) {
      console.error("[Supabase Auth] No user object returned.");
      throw {
        message:
          "No user object returned. Something went wrong during verification.",
        status: 500,
      } satisfies AuthError;
    }

    console.log("[User Profile]", data.user);
    return data;
  } catch (err: unknown) {
    const fallback = err as AuthError;
    console.error("[User Verification Failed]", fallback.message);
    throw {
      message: fallback?.message || "Unexpected error during verification.",
      status: fallback?.status || 500,
    };
  }
};
