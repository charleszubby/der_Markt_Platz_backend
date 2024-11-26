import express from "express";
import {
  createUser,
  verifyUser,
  loginUser,
  logOutUser,
  authMiddlWare,
} from "../../controllers/auth/auth.controllers.js";

const authRoute = express.Router();

authRoute.post("/create-user", createUser);
authRoute.post("/login-user", loginUser);
authRoute.post("/verify-user", verifyUser);
authRoute.post("/logout", logOutUser);
authRoute.get("/check-auth", authMiddlWare, (req, res) => {
  const user = req.user;
  res.status(200).json({
    success: true,
    message: "Authenticated user!",
    user,
  });
});
export { authRoute };
