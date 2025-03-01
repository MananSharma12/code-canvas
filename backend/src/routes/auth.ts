import express from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import pool from '../db'
import { SignupSchema, LoginSchema } from "../schemas/auth";

const router = express.Router();

router.post("/signup", async (req, res) => {
    try {
        const { email, password } = SignupSchema.safeParse(req.body);
        const hashedPassword = await bcrypt.hash(password, 10);

        const { rows } = await pool.query(
            'INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email',
            [email, hashedPassword],
        )
        res.status(201).json(rows[0]);
    } catch (error) {
        res.status(400).json({
            error: error.message,
        })
    }
})

router.post("/login", async (req, res) => {
    try {
        const { email, password } = LoginSchema.safeParse(req.body);

        const { rows } = await pool.query(
            'SELECT id, password_hash FROM users WHERE email = $1',
            [email],
        )

        if (!rows[0] || !(await bcrypt.compare(password, rows[0].password_hash))) {
            return res.status(401).json({
                error: 'Invalid login credentials'
            });
        }

        const token = jwt.sign({ userId: rows[0].id }, process.env.JWT_SECRET!, {
            expiresIn: '1d'
        });

        res.json({ token });
    } catch (error) {
        res.status(400).json({
            error
        })
    }
});

export default router;
