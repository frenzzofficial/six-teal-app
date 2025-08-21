// routes/testRoutes.ts
import { Router } from "express";
import { supabase } from "../../libs/db/db.supabase";

const testRoutes: ReturnType<typeof Router> = Router();

// 🔍 Basic connectivity check
testRoutes.get("/supabase-test", async (_, res) => {
  const { data, error } = await supabase.from("test").select("*").limit(1);
  if (error) {
    return res.status(500).json({
      status: "error",
      message: "Supabase connection failed",
      details: error.message,
    });
  }
  res.json({
    status: "success",
    message: "Supabase connected successfully",
    sample: data,
  });
});

// ➕ Inserting a test user
testRoutes.post("/supabase-test", async (req, res) => {
  const { email, username } = req.body as { email: string; username: string };
  console.log(email, username);

  if (!email || !username) {
    return res.status(400).json({
      status: "error",
      message: "Missing required fields",
      details: "email and username are required",
    });
  }

  const { data, error } = await supabase
    .from("test")
    .insert([{ username, email }]);
  if (error) {
    return res.status(500).json({
      status: "error",
      message: "Insert failed",
      details: error.message,
    });
  }
  res.status(201).json({
    status: "success",
    message: "User inserted successfully",
    data,
  });
});

export default testRoutes;
