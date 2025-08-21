import path from "path";
import express, { type Request, type Response } from "express";

//middlewares plugins
import helmet from "helmet";
import cookieParser from "cookie-parser";
import { corsMiddleware } from "./libs/middlewares/cors";
import { generalLimiter } from "./libs/middlewares/rateLimit";

//routes handlers
import testRoutes from "./api/test/test.routes";
import authRoutes from "./api/v01/auth/auth.routes";
import { errorHandler, NotFoundHandler } from "./libs/utils/NotFoundHandler";

const createApp = async (): Promise<express.Express> => {
  const app = express();
  // Trust proxy for Vercel
  app.set("trust proxy", 1);
  // Body parsing middleware
  app.use(express.json({ limit: "10mb" }));
  app.use(express.urlencoded({ extended: true }));

  // plugins
  // Rate limiting
  app.use(
    helmet({
      contentSecurityPolicy: process.env.NODE_ENV === "production",
      crossOriginEmbedderPolicy: false,
    })
  );
  app.use(generalLimiter);
  app.use(corsMiddleware);
  // Cookie parser
  app.use(cookieParser());

  // Static assets
  const viewsPath = path.join(process.cwd(), "public", "views");
  app.use(express.static(viewsPath));

  // Routes
  app.get(["/", "/index", "/index.html"], (_req: Request, res: Response) => {
    res
      .type("html")
      .set({
        "Content-Security-Policy":
          "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'",
        "Cache-Control": "no-cache, no-store, must-revalidate",
        Pragma: "no-cache",
        Expires: "0",
      })
      .sendFile(path.join(viewsPath, "index.html"));
  });

  //register api routes
  app.use("/api/test", testRoutes);
  app.use("/api/auth", authRoutes);

  app.get("/api/health", (_req: Request, res: Response) => {
    res.status(200).json({
      success: true,
      message: "Server is healthy",
      timestamp: new Date().toISOString(),
      environment: process.env.NODE_ENV,
    });
  });

  // Catch-all 404 handler
  app.use(NotFoundHandler);
  // Error handling middleware (must be last)
  app.use(errorHandler);

  return app;
};

// Ensure the promise is handled
const appPromise = createApp();

export default appPromise;
