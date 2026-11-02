import { NextRequest, NextResponse } from "next/server";
import { getServerSession } from "next-auth";
import { authOptions } from "@/lib/auth";
import { verifyLinkToken, linkTelegramToAccount, getLinkedTelegram } from "@/lib/db";

export const runtime = "nodejs";

export async function GET() {
    try {
        const session = await getServerSession(authOptions);
        if (!session?.user?.id) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
        const linkedTelegram = await getLinkedTelegram(session.user.id);
        return NextResponse.json({ linked: !!linkedTelegram, telegramId: linkedTelegram });
    } catch (error) {
        console.error("Link status error:", error);
        return NextResponse.json({ error: "Could not retrieve link status." }, { status: 500 });
    }
}

export async function POST(req: NextRequest) {
    try {
        const session = await getServerSession(authOptions);
        if (!session?.user?.id) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
        const length = Number(req.headers.get("content-length") || 0);
        if (length > 4096) return NextResponse.json({ error: "Request too large" }, { status: 413 });

        const origin = req.headers.get("origin");
        const host = req.headers.get("x-forwarded-host") || req.headers.get("host");
        if (!origin || !host) return NextResponse.json({ error: "Missing request origin" }, { status: 403 });
        try {
            if (new URL(origin).host !== host) return NextResponse.json({ error: "Invalid request origin" }, { status: 403 });
        } catch {
            return NextResponse.json({ error: "Invalid request origin" }, { status: 403 });
        }

        const body = await req.json();
        const token = typeof body?.token === "string" ? body.token.trim() : "";
        if (!/^[a-f0-9]{32}$/i.test(token)) {
            return NextResponse.json({ error: "Invalid or expired token" }, { status: 400 });
        }
        const telegramId = await verifyLinkToken(token);
        if (!telegramId) return NextResponse.json({ error: "Invalid or expired token" }, { status: 400 });
        await linkTelegramToAccount(String(telegramId), session.user.id);
        return NextResponse.json({ success: true, message: "Telegram account linked successfully" });
    } catch (error) {
        console.error("Link error:", error);
        return NextResponse.json({ error: "Link failed. Please try again." }, { status: 500 });
    }
}
