import { Router } from "express";
import * as authControllers from "./auth.controllers";

const authRoutes: ReturnType<typeof Router> = Router();

//all api routes for auth services
authRoutes.post("/login", authControllers.loginAuthController);
authRoutes.post("/logout", authControllers.logoutAuthController);
authRoutes.post("/register", authControllers.registerAuthController);
authRoutes.post("/verify-email", authControllers.verifyEmailAuthController);
authRoutes.post("/reset-password", authControllers.resetPasswordAuthController);
authRoutes.post(
  "/forgot-password",
  authControllers.forgotPasswordAuthController
);

export default authRoutes;
