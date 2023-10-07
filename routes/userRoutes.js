import express from "express";
import {
  forgotPasswordController,
  loginController,
  registerController,
  resetPasswordController,
} from "../controllers/userController.js";

const router = express.Router();

router.post("/login", loginController);

router.post("/register", registerController);

router.post("/forgot-password", forgotPasswordController);

router.post("/reset-password", resetPasswordController);

export default router;
