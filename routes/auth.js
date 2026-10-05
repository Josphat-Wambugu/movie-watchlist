import express from "express";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import { findByUsername } from "../utils/db.js";

const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET || "your-secret-key";

router.post("/login", async (req, res) => {
    const { username, password } = req.body;

    // Validate missing fields
    if (!username || !password) {
        return res.status(400).json({ error: "Username and password are required." });
    }

    // Find user by username
    const user = findByUsername(username);
    if (!user) {
        return res.status(401).json({ error: "Invalid credentials." });
    }

    // Compare hashed password
    const isPasswordValid = await bcrypt.compare(password, user.passwordHash);
    if (!isPasswordValid) {
        return res.status(401).json({ error: "Invalid credentials." });
    }

    // Generate JWT token
    const token = jwt.sign(
        { id: user.id, username: user.username, role: user.role },
        JWT_SECRET,
        { expiresIn: "1h" }
    );

    return res.status(200).json({ token });
});

export default router;