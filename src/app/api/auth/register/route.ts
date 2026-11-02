import { NextRequest, NextResponse } from "next/server";
import { Redis } from "@upstash/redis";
import bcrypt from "bcryptjs";
import { createHash, randomUUID } from "node:crypto";

export const runtime = "nodejs";

const redisUrl = process.env.UPSTASH_REDIS_REST_URL?.trim();
const redisToken = process.env.UPSTASH_REDIS_REST_TOKEN?.trim();
if (!redisUrl || !redisToken) throw new Error("Redis credentials are required for registration.");
const redis = new Redis({ url: redisUrl, token: redisToken });

async function allow(key: string, limit: number, windowSeconds: number): Promise<boolean> {
    const count = await redis.eval<number>(
        "local n = redis.call('INCR', KEYS[1]); if n == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]); end; return n",
        [key],
        [String(windowSeconds)]
    );
    return Number(count) <= limit;
}

export async function POST(req: NextRequest) {
    try {
        const contentLength = Number(req.headers.get("content-length") || 0);
        if (Number.isFinite(contentLength) && contentLength > 16 * 1024) {
            return NextResponse.json({ error: "Request too large" }, { status: 413 });
        }
        const ip = (req.headers.get("x-real-ip") || req.headers.get("x-forwarded-for") || "unknown")
            .split(",")[0].trim().slice(0, 128) || "unknown";
        const ipHash = createHash("sha256").update(ip).digest("hex");
        if (!await allow(`ratelimit:register:${ipHash}`, 5, 3600)) {
            return NextResponse.json({ error: "Too many registration attempts. Try again later." }, { status: 429 });
        }

        const body = await req.json();
        const rawEmail = typeof body?.email === "string" ? body.email : "";
        const email = rawEmail.trim().toLowerCase();
        const password = typeof body?.password === "string" ? body.password : "";
        const name = typeof body?.name === "string" ? body.name.trim() : "";

        if (!email || !password) return NextResponse.json({ error: "Email and password are required." }, { status: 400 });
        if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            return NextResponse.json({ error: "Please provide a valid email address." }, { status: 400 });
        }
        if (password.length < 12 || password.length > 128) {
            return NextResponse.json({ error: "Password must be between 12 and 128 characters." }, { status: 400 });
        }
        if (name.length > 80) return NextResponse.json({ error: "Name must be 80 characters or fewer." }, { status: 400 });

        const id = randomUUID();
        const passwordHash = await bcrypt.hash(password, 12);
        const safeName = name || email.split("@")[0];
        const now = new Date().toISOString();
        const user = {
            id, name: safeName, email, passwordHash, emailVerified: null,
            image: `https://ui-avatars.com/api/?name=${encodeURIComponent(safeName)}&background=random`,
            createdAt: now, updatedAt: now
        };

        // Atomically claim the normalized email and create the user document.
        const created = await redis.eval<number>(
            "if redis.call('EXISTS', KEYS[1]) == 1 then return 0 end; redis.call('SET', KEYS[2], ARGV[2]); redis.call('SET', KEYS[1], ARGV[1]); return 1",
            [`user:email:${email}`, `user:${id}`],
            [id, JSON.stringify(user)]
        );
        if (Number(created) !== 1) return NextResponse.json({ error: "User already exists" }, { status: 409 });
        return NextResponse.json({ success: true });
    } catch (error) {
        console.error("Register Error:", error);
        return NextResponse.json({ error: "Registration failed. Please try again." }, { status: 500 });
    }
}
