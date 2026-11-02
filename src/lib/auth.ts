import { NextAuthOptions } from "next-auth";
import GithubProvider from "next-auth/providers/github";
import GoogleProvider from "next-auth/providers/google";
import CredentialsProvider from "next-auth/providers/credentials";
import { UpstashRedisAdapter } from "@auth/upstash-redis-adapter";
import { Redis } from "@upstash/redis";
import bcrypt from "bcryptjs";
import { createHash, createHmac, timingSafeEqual } from "node:crypto";

declare module "next-auth" {
    interface Session {
        user: {
            id?: string;
            name?: string | null;
            email?: string | null;
            image?: string | null;
        }
    }
}

const redisUrl = process.env.UPSTASH_REDIS_REST_URL?.trim();
const redisToken = process.env.UPSTASH_REDIS_REST_TOKEN?.trim();
if (!redisUrl || !redisToken) throw new Error("Upstash Redis credentials are required for authentication.");
const redis = new Redis({ url: redisUrl, token: redisToken });

const RATE_WINDOW_SECONDS = 15 * 60;

async function rateLimitAllowed(key: string, limit: number, windowSeconds = RATE_WINDOW_SECONDS): Promise<boolean> {
    const count = await redis.eval<number>(
        "local n = redis.call('INCR', KEYS[1]); if n == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]); end; return n",
        [key],
        [String(windowSeconds)]
    );
    return Number(count) <= limit;
}

function getClientIp(headers: Record<string, string | undefined> | undefined): string {
    const raw = headers?.["x-real-ip"] || headers?.["x-forwarded-for"] || "unknown";
    return raw.split(",")[0].trim().slice(0, 128) || "unknown";
}

function safeHashEqual(expectedHex: string, suppliedHex: string): boolean {
    if (!/^[a-f0-9]{64}$/i.test(suppliedHex)) return false;
    const expected = Buffer.from(expectedHex, "hex");
    const supplied = Buffer.from(suppliedHex, "hex");
    return expected.length === supplied.length && timingSafeEqual(expected, supplied);
}

export const authOptions: NextAuthOptions = {
    // @ts-ignore - adapter package exposes a narrower type than NextAuthOptions.
    adapter: UpstashRedisAdapter(redis),
    session: { strategy: "jwt" },
    pages: { signIn: "/login" },
    providers: [
        GithubProvider({
            clientId: process.env.GITHUB_ID || "",
            clientSecret: process.env.GITHUB_SECRET || "",
        }),
        GoogleProvider({
            clientId: process.env.GOOGLE_CLIENT_ID || "",
            clientSecret: process.env.GOOGLE_CLIENT_SECRET || "",
        }),
        CredentialsProvider({
            name: "Credentials",
            credentials: {
                email: { label: "Email", type: "email" },
                password: { label: "Password", type: "password" }
            },
            async authorize(credentials, req) {
                if (!credentials?.email || !credentials?.password) return null;
                const email = credentials.email.trim().toLowerCase();
                if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return null;

                const ipHash = createHash("sha256").update(getClientIp(req?.headers)).digest("hex");
                const emailHash = createHash("sha256").update(email).digest("hex");
                const [ipAllowed, emailAllowed] = await Promise.all([
                    rateLimitAllowed(`ratelimit:auth:password:ip:${ipHash}`, 30),
                    rateLimitAllowed(`ratelimit:auth:password:email:${emailHash}`, 10)
                ]);
                if (!ipAllowed || !emailAllowed) return null;

                let userId = await redis.get<string>(`user:email:${email}`);
                // Existing installations may contain pre-normalized email keys.
                if (!userId && credentials.email.trim() !== email) {
                    userId = await redis.get<string>(`user:email:${credentials.email.trim()}`);
                }
                if (!userId) return null;
                const user: any = await redis.get(`user:${userId}`);
                if (!user?.passwordHash || user.emailVerified === false) return null;
                if (!await bcrypt.compare(credentials.password, user.passwordHash)) return null;
                return { id: String(user.id || userId), name: user.name, email: user.email, image: user.image };
            }
        }),
        CredentialsProvider({
            id: "telegram-login",
            name: "Telegram",
            credentials: {
                telegram_id: { label: "Telegram ID", type: "text" },
                id: { label: "ID", type: "text" },
                first_name: { label: "First Name", type: "text" },
                last_name: { label: "Last Name", type: "text" },
                username: { label: "Username", type: "text" },
                photo_url: { label: "Photo URL", type: "text" },
                auth_date: { label: "Auth Date", type: "text" },
                hash: { label: "Hash", type: "text" }
            },
            async authorize(credentials, req) {
                const botToken = process.env.TELEGRAM_BOT_TOKEN?.trim();
                if (!credentials?.hash || !botToken) return null;
                const rawId = credentials.telegram_id && credentials.telegram_id !== "telegram-login"
                    ? credentials.telegram_id : credentials.id;
                if (!rawId || !/^\d{1,20}$/.test(rawId)) return null;

                const authDateRaw = credentials.auth_date || "";
                if (!/^\d{1,12}$/.test(authDateRaw)) return null;
                const authDate = Number(authDateRaw);
                const now = Math.floor(Date.now() / 1000);
                if (!Number.isSafeInteger(authDate) || authDate > now + 60 || now - authDate > 300) return null;

                const ipHash = createHash("sha256").update(getClientIp(req?.headers)).digest("hex");
                if (!await rateLimitAllowed(`ratelimit:auth:telegram-widget:ip:${ipHash}`, 30)) return null;

                const user: Record<string, string> = { id: rawId };
                for (const key of ["first_name", "last_name", "username", "photo_url"] as const) {
                    const value = credentials[key];
                    if (value && value !== "undefined") user[key] = value;
                }
                user.auth_date = authDateRaw;

                const checkString = Object.keys(user).sort().map(key => `${key}=${user[key]}`).join("\n");
                const secret = createHash("sha256").update(botToken).digest();
                const expected = createHmac("sha256", secret).update(checkString).digest("hex");
                if (!safeHashEqual(expected, credentials.hash)) return null;

                const replayKey = `telegram:auth_replay:${createHash("sha256").update(credentials.hash).digest("hex")}`;
                const claimed = await redis.set(replayKey, "1", { ex: 300, nx: true });
                if (claimed !== "OK") return null;

                const name = credentials.last_name
                    ? `${credentials.first_name || ""} ${credentials.last_name}`.trim()
                    : (credentials.first_name || credentials.username || "Telegram User");
                return { id: rawId, name, image: credentials.photo_url || null, email: `${rawId}@telegram.user` };
            }
        }),
        CredentialsProvider({
            id: "telegram-pin",
            name: "Telegram PIN",
            credentials: { pin: { label: "PIN", type: "text" } },
            async authorize(credentials, req) {
                const pin = credentials?.pin?.trim() || "";
                if (!/^\d{6}$/.test(pin)) return null;
                const ipHash = createHash("sha256").update(getClientIp(req?.headers)).digest("hex");
                if (!await rateLimitAllowed(`ratelimit:auth:telegram-pin:ip:${ipHash}`, 10)) return null;

                // Atomic consume. Only one request can ever authenticate with a given PIN.
                const data: any = await redis.eval<string | null>(
                    "return redis.call('GETDEL', KEYS[1])",
                    [`telegram:login_pin:${pin}`],
                    []
                );
                if (!data) return null;
                let userData: any;
                try { userData = typeof data === "string" ? JSON.parse(data) : data; }
                catch { return null; }
                if (!userData?.id || !/^\d{1,20}$/.test(String(userData.id))) return null;
                return {
                    id: String(userData.id),
                    name: userData.first_name || userData.name || "Telegram User",
                    image: userData.photo_url || null,
                    email: `${userData.id}@telegram.user`
                };
            }
        })
    ],
    callbacks: {
        async session({ session, token }) {
            if (session.user && token.sub) {
                session.user.id = token.sub;
                try {
                    const avatar: string | null = await redis.get(`user:custom_avatar:${token.sub}`);
                    if (avatar) session.user.image = avatar;
                    else if (token.picture) session.user.image = token.picture as string;
                } catch { /* Keep JWT picture as fallback. */ }
            }
            return session;
        },
        async jwt({ token, user, account }) {
            if (account && user) {
                token.sub = user.id;
                if (user.image) token.picture = user.image;
            }
            return token;
        }
    }
};
