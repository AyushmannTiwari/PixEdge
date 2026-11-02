import { NextRequest, NextResponse } from 'next/server';
import { uploadToTelegram } from '@/lib/telegram';
import { saveImage, generateId, getImage, rateLimit } from '@/lib/db';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth';
import { validateCustomId } from '@/lib/slugs';
import { createHash } from 'node:crypto';

export const runtime = 'nodejs';

function extensionForMime(mimeType: string): string {
    const type = (mimeType || '').split(';')[0].trim().toLowerCase();
    const map: Record<string, string> = {
        'image/jpeg': '.jpg', 'image/jpg': '.jpg', 'image/png': '.png',
        'image/gif': '.gif', 'image/webp': '.webp', 'image/avif': '.avif',
        'video/mp4': '.mp4', 'video/webm': '.webm', 'video/quicktime': '.mov',
        'video/x-matroska': '.mkv'
    };
    return map[type] || '.bin';
}

export async function POST(req: NextRequest) {
    let file: File | null = null;
    let reservationKey: string | null = null;
    let reservationHeld = false;
    try {
        const session = await getServerSession(authOptions);
        const userId = session?.user?.id || undefined;
        const forwarded = req.headers.get('x-real-ip') || req.headers.get('x-forwarded-for') || 'anonymous';
        const ip = forwarded.split(',')[0].trim().slice(0, 128) || 'anonymous';
        const limit = await rateLimit(userId ? `simple-upload:user:${userId}` : `simple-upload:ip:${ip}`, userId ? 100 : 20, 60);
        if (!limit.success) {
            return NextResponse.json({ error: 'Too many uploads. Please try again shortly.' }, { status: 429 });
        }

        const formData = await req.formData();
        const entry = formData.get('file');
        if (!(entry instanceof File)) {
            return NextResponse.json({ error: 'No file provided' }, { status: 400 });
        }
        file = entry;

        const allowed = new Set([
            'image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/avif',
            'video/mp4', 'video/webm', 'video/quicktime', 'video/x-matroska'
        ]);
        const mimeType = (file.type || '').split(';')[0].trim().toLowerCase();
        if (!allowed.has(mimeType)) {
            return NextResponse.json({ error: 'Unsupported image or video format' }, { status: 415 });
        }
        const gramReady = (await import('@/lib/gramjs')).isGramConfigured();
        const maxMB = gramReady ? Math.max(1, Number.parseInt(process.env.MAX_UPLOAD_SIZE_MB || '2000', 10) || 2000) : 50;
        if (!Number.isFinite(file.size) || file.size <= 0 || file.size > maxMB * 1024 * 1024) {
            return NextResponse.json({ error: `File size must be between 1 byte and ${maxMB} MB.` }, { status: 400 });
        }

        const customId = formData.get('customId');
        let id = generateId();
        if (typeof customId === 'string' && customId.trim()) {
            const validation = validateCustomId(customId.trim());
            if (!validation.valid || !validation.sanitized) {
                return NextResponse.json({ error: validation.error || 'Invalid custom ID' }, { status: 400 });
            }
            id = validation.sanitized;
            if (await getImage(id)) return NextResponse.json({ error: 'This ID is already taken' }, { status: 409 });

            const { Redis } = await import('@upstash/redis');
            const redisUrl = process.env.UPSTASH_REDIS_REST_URL?.trim();
            const redisToken = process.env.UPSTASH_REDIS_REST_TOKEN?.trim();
            if (!redisUrl || !redisToken) return NextResponse.json({ error: 'Custom IDs require Redis' }, { status: 503 });
            const lockRedis = new Redis({ url: redisUrl, token: redisToken });
            reservationKey = `slug:reservation:${id}`;
            const reserved = await lockRedis.set(reservationKey, userId || ip, { ex: 600, nx: true });
            if (reserved !== 'OK') return NextResponse.json({ error: 'This ID is currently being claimed' }, { status: 409 });
            reservationHeld = true;
        }

        const result = await uploadToTelegram(file, `upload${extensionForMime(mimeType)}`);
        await saveImage({
            id,
            telegram_file_id: result.file_id,
            created_at: Date.now(),
            metadata: { size: file.size, type: mimeType, version: 'v1' }
        }, 'web', userId);

        if (reservationHeld && reservationKey) {
            const { Redis } = await import('@upstash/redis');
            const lockRedis = new Redis({ url: process.env.UPSTASH_REDIS_REST_URL!, token: process.env.UPSTASH_REDIS_REST_TOKEN! });
            await lockRedis.del(reservationKey);
            reservationHeld = false;
        }

        const baseUrl = process.env.NEXT_PUBLIC_BASE_URL;
        if (!baseUrl) throw new Error('NEXT_PUBLIC_BASE_URL is not configured');
        return NextResponse.json({
            id,
            url: `${baseUrl}/i/${id}`,
            direct_url: `${baseUrl}/i/${id}${extensionForMime(mimeType)}`
        });
    } catch (error) {
        console.error('Upload error:', error);
        return NextResponse.json({ error: 'Upload could not be completed.' }, { status: 500 });
    } finally {
        if (reservationHeld && reservationKey) {
            try {
                const { Redis } = await import('@upstash/redis');
                const lockRedis = new Redis({ url: process.env.UPSTASH_REDIS_REST_URL!, token: process.env.UPSTASH_REDIS_REST_TOKEN! });
                await lockRedis.del(reservationKey);
            } catch (releaseError) {
                console.error('Could not release ID reservation:', releaseError);
            }
        }
    }
}
