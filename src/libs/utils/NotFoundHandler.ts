import { type Request, type Response, type NextFunction } from "express";

export interface AppError extends Error {
  statusCode?: number;
  isOperational?: boolean;
}

export const NotFoundHandler = (req: Request, res: Response): void => {
  const acceptsJson = req.accepts("json");
  const acceptsHtml = req.accepts("html");

  res.status(404);

  if (acceptsJson) {
    res.json({
      success: false,
      message: `Route ${req.originalUrl} not found`,
    });
  } else if (acceptsHtml) {
    res.type("html").send("<h1>404 - Not Found</h1>");
  } else {
    res.type("text").send("Error 404: Not Found");
  }
};

// Error handling middleware
export const errorHandler = (
  error: AppError,
  req: Request,
  res: Response,
  next: NextFunction
) => {
  let statusCode = error.statusCode || 500;
  let message = error.message || "Internal Server Error";

  // Handle specific error types
  if (error.name === "SequelizeValidationError") {
    statusCode = 400;
    message = "Validation error";
  }

  if (error.name === "SequelizeUniqueConstraintError") {
    statusCode = 400;
    message = "Resource already exists";
  }

  if (error.name === "JsonWebTokenError") {
    statusCode = 401;
    message = "Invalid token";
  }

  if (error.name === "TokenExpiredError") {
    statusCode = 401;
    message = "Token expired";
  }

  // Log error in development
  if (process.env.NODE_ENV === "development") {
    console.error("Error Details:", {
      message: error.message,
      stack: error.stack,
      statusCode,
      path: req.path,
      method: req.method,
      timestamp: new Date().toISOString(),
    });
  }

  // Send error response
  res.status(statusCode).json({
    success: false,
    message,
    ...(process.env.NODE_ENV === "development" && {
      stack: error.stack,
      error: error.name,
    }),
  });
  next();
};

// Async error wrapper
// eslint-disable-next-line @typescript-eslint/no-unsafe-function-type
export const asyncHandler = (fn: Function) => {
  return (req: Request, res: Response, next: NextFunction) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
};
