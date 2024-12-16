import crypto from 'crypto';
import { CreateLogger } from '../utils';

const logs = CreateLogger();

export function CreateContentDigest(jsonString: string): string {
    try {
        const jsonData = JSON.parse(jsonString);
        const jsonBytes = Buffer.from(JSON.stringify(jsonData, null, 2));
        const hash = crypto.createHash('sha512');
        hash.update(jsonBytes);
        const hashedJsonBytes = hash.digest();
        const strBase64 = hashedJsonBytes.toString('base64');
        return `sha-512=:${strBase64}:`;
    } catch (error) {
        const errorMessage = error instanceof Error
            ? `Invalid JSON input: ${error.message}`
            : 'Invalid JSON input';
        logs.error(errorMessage);
        throw new Error(errorMessage);
    }
}

export function VerifyContentDigest(
    body: string,
    contentDigestHeader: string | undefined
): boolean {
    if (!contentDigestHeader) {
        const errorMessage = 'Content-Digest header is missing';
        logs.error(errorMessage);
        throw new Error(errorMessage);
    }

    try {
        const computedDigest = CreateContentDigest(body);
        return computedDigest === contentDigestHeader;
    } catch (error) {
        if (error instanceof Error) {
            throw error; // Re-throw createContentDigest errors
        }
        const errorMessage = 'Failed to verify content digest';
        logs.error(errorMessage);
        throw new Error(errorMessage);
    }
}