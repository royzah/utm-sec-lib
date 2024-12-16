import crypto, { KeyObject, generateKeyPair } from 'crypto';
import fs from 'fs';
import { promisify } from 'util';

const generateKeyPairAsync = promisify(generateKeyPair);

const ELLIPTIC_CURVE = 'prime256v1';
const DEFAULT_RSA_KEY_SIZE = 4096;

export interface RsaOptions {
    keySize: number;
}

const randomSeedBytes = crypto.randomBytes(32);

export async function CreateEcdsaPrivateKey(): Promise<KeyObject> {
    try {
        const { privateKey } = await generateKeyPairAsync('ec', {
            namedCurve: ELLIPTIC_CURVE,
        });
        return privateKey;
    } catch (error) {
        const message = error instanceof Error ? error.message : 'Unknown error';
        throw new Error(`Failed to generate ECDSA private key: ${message}`);
    }
}

export async function CreateEd25519PrivateKey(): Promise<KeyObject> {
    try {
        const { privateKey } = await generateKeyPairAsync('ed25519', {
            seedLength: 32,
            seed: randomSeedBytes,
        });
        return privateKey;
    } catch (error) {
        const message = error instanceof Error ? error.message : 'Unknown error';
        throw new Error(`Failed to generate Ed25519 private key: ${message}`);
    }
}

export async function CreateRSAPSSPrivateKey(rsaOptions?: RsaOptions): Promise<KeyObject> {
    const keySize = rsaOptions?.keySize || DEFAULT_RSA_KEY_SIZE;
    try {
        const { privateKey } = await generateKeyPairAsync('rsa', {
            modulusLength: keySize,
            publicExponent: 0x10001,
        });
        return privateKey;
    } catch (error) {
        const message = error instanceof Error ? error.message : 'Unknown error';
        throw new Error(`Failed to generate RSA-PSS private key: ${message}`);
    }
}

export function GetPrivateKeyAsPemBytes(privateKey: KeyObject): Buffer {
    if (privateKey.type !== 'private') {
        throw new Error('Not a private key');
    }

    if (!IsSupportedKey(privateKey)) {
        throw new Error('Private key not supported');
    }

    try {
        return Buffer.from(privateKey.export({
            type: 'pkcs8',
            format: 'pem'
        }));
    } catch (error) {
        const message = error instanceof Error ? error.message : 'Unknown error';
        throw new Error(`Failed to export private key as PEM: ${message}`);
    }
}

export function GetKeyTypeLabel(key: KeyObject): string {
    if (!key) {
        throw new Error('Key is null');
    }

    switch (key.asymmetricKeyType) {
        case 'rsa-pss':
        case 'rsa':
            return 'RSA';
        case 'ec':
            return 'ECDSA';
        case 'ed25519':
            return 'Ed25519';
        default:
            throw new Error('Unsupported key type');
    }
}

export async function SavePrivateKeyToFile(privateKey: KeyObject, filePath: string): Promise<number> {
    await validateKeyFileParameters(privateKey, filePath);

    try {
        // Check if file exists
        if (fs.existsSync(filePath)) {
            throw new Error('File already exists');
        }

        const pemBytes = GetPrivateKeyAsPemBytes(privateKey);
        await fs.promises.writeFile(filePath, pemBytes);
        return pemBytes.length;
    } catch (error) {
        const message = error instanceof Error ? error.message : 'Unknown error';
        throw new Error(`Failed to save private key to file: ${message}`);
    }
}

export async function LoadPrivateKeyFromFile(filePath: string): Promise<KeyObject> {
    try {
        const pemBytes = await fs.promises.readFile(filePath);
        return crypto.createPrivateKey(pemBytes);
    } catch (error) {
        const message = error instanceof Error ? error.message : 'Unknown error';
        throw new Error(`Failed to load private key from file: ${message}`);
    }
}

async function validateKeyFileParameters(key: KeyObject, path: string): Promise<void> {
    if (!key) {
        throw new Error('Private key is null');
    }

    if (!IsSupportedKey(key)) {
        throw new Error('Private key not supported');
    }

    if (!path) {
        throw new Error('Path is empty');
    }
}

export function IsSupportedKey(key: KeyObject): boolean {
    if (!key) return false;

    const supportedTypes = ['rsa', 'rsa-pss', 'ec', 'ed25519'];
    return supportedTypes.includes(key.asymmetricKeyType || '');
}