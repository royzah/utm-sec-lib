import { PublicKeyInput } from 'crypto';
import { CreateLogger } from '../utils';

const logs = CreateLogger();

interface JWK {
    alg: string;
    kty: string;
    kid: string;
    n?: string;  // For RSA
    e?: string;  // For RSA
    x?: string;  // For EC
    y?: string;  // For EC
}

interface JWKResponse {
    keys: JWK[];
}

export function GetJwkFromPublicKey(publicKey: PublicKeyInput, keyId: string): JWK {
    try {
        if (typeof publicKey !== 'object') {
            throw new Error('Invalid public key format');
        }

        // RSA Key handling
        if ('n' in publicKey && 'e' in publicKey) {
            const n = Buffer.from(publicKey.n as string, 'base64');
            const e = Buffer.from(publicKey.e as string, 'base64');

            return {
                alg: 'PS512',
                kty: 'RSA',
                kid: keyId,
                n: n.toString('base64url'),
                e: e.toString('base64url')
            };
        }
        
        // EC Key handling
        if ('x' in publicKey && 'y' in publicKey) {
            const x = Buffer.from(publicKey.x as string, 'base64');
            const y = Buffer.from(publicKey.y as string, 'base64');

            return {
                alg: 'ES512',
                kty: 'EC',
                kid: keyId,
                x: x.toString('base64url'),
                y: y.toString('base64url')
            };
        }

        throw new Error('Unsupported public key type');
    } catch (error) {
        const message = error instanceof Error ? error.message : 'Unknown error creating JWK';
        logs.error(`Error creating JWK: ${message}`);
        throw new Error(`Failed to create JWK: ${message}`);
    }
}

export function BuildJWKResponse(publicKeys: Record<string, JWK>): JWKResponse {
    try {
        const jwkArray = Object.values(publicKeys);

        jwkArray.sort((a, b) => a.alg.localeCompare(b.alg));

        return {
            keys: jwkArray
        };
    } catch (error) {
        const message = error instanceof Error ? error.message : 'Unknown error building JWK response';
        logs.error(`Error building JWK response: ${message}`);
        throw new Error(`Failed to build JWK response: ${message}`);
    }
}

export function ValidateJWK(jwk: JWK): boolean {
    if (!jwk.alg || !jwk.kty || !jwk.kid) {
        throw new Error('Missing required JWK fields (alg, kty, or kid)');
    }

    if (jwk.kty === 'RSA' && (!jwk.n || !jwk.e)) {
        throw new Error('RSA JWK missing required fields (n or e)');
    }

    if (jwk.kty === 'EC' && (!jwk.x || !jwk.y)) {
        throw new Error('EC JWK missing required fields (x or y)');
    }

    return true;
}