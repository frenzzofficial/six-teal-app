import { Express } from "express";
import appPromise from "../src/app";
import { VercelRequest, VercelResponse } from "@vercel/node";

// ✅ Production-ready Vercel handler
export default async function handler(
  req: VercelRequest,
  res: VercelResponse
): Promise<void> {
  try {
    const app = await appPromise;

    // Optional: narrow casting if you're certain these types align
    (app as Express)(req, res);
  } catch (err) {
    console.error("❌ Error handling Vercel request:", err);

    res.status(500).json({
      success: false,
      message: "Internal Server Error",
    });
  }
}
