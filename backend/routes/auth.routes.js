import express from "express";
import { login, logout, signup } from "../controllers/auth.controller.js";

const router = express.Router();

router.get("/signup", signup);

router.get("/login", (req, res) => login);

router.get("/logout", (req, res) => logout);

export default router;
