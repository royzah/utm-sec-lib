import crypto from 'crypto';
import fs from 'fs';
import { CreateLogger } from '../utils';

const logs = CreateLogger();

type AsymmetricKeyType = 'rsa' | 'ec' | 'ed25519';

interface JWK {
    kty: string;
    n?: string;  // for RSA
    e?: string;  // for RSA
    kid: string;
    alg: string;
    crv?: string; // for EC
    x?: string;   // for EC
    y?: string;   // for EC
}

function createSignerWithAlgorithm(algorithm: string) {
    try {
        return crypto.createSign(algorithm);
    } catch (error) {
        const message = `Failed to create signer: ${error}`;
        logs.error(message);
        throw new Error(message);
    }
}

function signWithOptions(signer: crypto.Sign, options: crypto.SignPrivateKeyInput | string): string {
    try {
        return signer.sign(options, 'base64');
    } catch (error) {
        const message = `Failed to sign data: ${error}`;
        logs.error(message);
        throw new Error(message);
    }
}

export function signDataWithRsaKey(privateKeyPem: string, signBase: Buffer): string {
    const signer = createSignerWithAlgorithm('sha512');
    signer.update(signBase);
    signer.end();

    return signWithOptions(signer, {
        key: privateKeyPem,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength: 64
    });
}

export function signDataWithEcdsaKey(privateKeyPem: string, signBase: Buffer): string {
    const signer = createSignerWithAlgorithm('sha256');
    signer.update(signBase);
    signer.end();

    return signWithOptions(signer, {
        key: privateKeyPem,
        dsaEncoding: 'ieee-p1363'
    });
}

export function signDataWithEd25519Key(privateKeyPem: string, signBase: Buffer): string {
    const signer = createSignerWithAlgorithm('sha512');
    signer.update(signBase);
    signer.end();

    return signWithOptions(signer, {
        key: privateKeyPem,
        format: 'pem',
        type: 'pkcs8'
    });
}

export function SignDataWithPrivateKey(privateKeyPem: string, signBase: Buffer): string {
    if (!privateKeyPem || !signBase) {
        throw new Error('Private key and sign base are required');
    }
    try {
        const keyType = crypto.createPrivateKey(privateKeyPem).asymmetricKeyType as AsymmetricKeyType;

        switch (keyType) {
            case 'rsa':
                logs.info('Signing with RSA');
                return signDataWithRsaKey(privateKeyPem, signBase);
            case 'ec':
                logs.info('Signing with ECDSA');
                return signDataWithEcdsaKey(privateKeyPem, signBase);
            case 'ed25519':
                logs.info('Signing with Ed25519');
                return signDataWithEd25519Key(privateKeyPem, signBase);
            default:
                const message = `Unsupported key type: ${keyType}`;
                logs.error(message);
                throw new Error(message);
        }
    } catch (error) {
        const message = `Failed to sign data: ${error}`;
        logs.error(message);
        throw new Error(message);
    }
}

function verifyEcdsaSignature(
    publicKeyPem: string,
    responseSignature: string,
    responseSignBase: string
): boolean {
    if (!responseSignBase?.trim()) {
        logs.error('Response signature base is empty');
        throw new Error('Response signature base is empty');
    }

    const verifier = crypto.createVerify('sha256');
    verifier.update(responseSignBase);

    return verifier.verify(
        {
            key: publicKeyPem,
            dsaEncoding: 'ieee-p1363'
        },
        responseSignature,
        'base64'
    );
}

function verifyRsaSignature(
    publicKeyPem: string,
    responseSignature: string,
    responseSignBase: string
): boolean {
    if (!responseSignBase?.trim()) {
        logs.error('Response signature base is empty');
        throw new Error('Response signature base is empty');
    }

    const verifier = crypto.createVerify('sha512');
    verifier.update(responseSignBase);
    return verifier.verify(publicKeyPem, responseSignature, 'base64');
}

function verifyEd25519Signature(
    publicKeyPem: string,
    responseSignature: string,
    responseSignBase: string
): boolean {
    if (!responseSignBase?.trim()) {
        logs.error('Response signature base is empty');
        throw new Error('Response signature base is empty');
    }

    try {
        const publicKey = crypto.createPublicKey({
            key: publicKeyPem,
            format: 'pem',
            type: 'spki'
        });

        return crypto.verify(
            null,
            Buffer.from(responseSignBase),
            publicKey,
            Buffer.from(responseSignature, 'base64')
        );
    } catch (error) {
        const message = `Failed to verify Ed25519 signature: ${error}`;
        logs.error(message);
        throw new Error(message);
    }
}

export function VerifyWithPublicKey(
    publicKeyPem: string,
    responseSignature: string,
    responseSignBase: string
): boolean {
    if (!publicKeyPem || !responseSignature || !responseSignBase) {
        throw new Error('Missing required parameters for signature verification');
    }

    try {
        const keyType = crypto.createPublicKey(publicKeyPem).asymmetricKeyType as AsymmetricKeyType;

        const signatureValue = responseSignature.includes(':') ?
            responseSignature.split(':')[1] : responseSignature;

        switch (keyType) {
            case 'ec':
                return verifyEcdsaSignature(publicKeyPem, signatureValue, responseSignBase);
            case 'rsa':
                return verifyRsaSignature(publicKeyPem, signatureValue, responseSignBase);
            case 'ed25519':
                return verifyEd25519Signature(publicKeyPem, signatureValue, responseSignBase);
            default:
                throw new Error(`Unsupported key type: ${keyType}`);
        }
    } catch (error) {
        logs.error('Signature verification failed:', {
            error,
            publicKeyType: typeof publicKeyPem,
            signatureValue: responseSignature
        });
        throw error;
    }
}

export function CreateCertificateBundle(clientCertPath: string): string {
    try {
        const derCert = fs.readFileSync(clientCertPath);
        return derCert.toString('base64');
    } catch (error) {
        const message = `Failed to create certificate bundle: ${error}`;
        logs.error(message);
        throw new Error(message);
    }
}

export function loadCertificateFromFile(certPath: string): Buffer {
    try {
        return fs.readFileSync(certPath);
    } catch (error) {
        const message = `Failed to load certificate: ${error}`;
        logs.error(message);
        throw new Error(message);
    }
}

export function saveCertificateToFile(certPath: string, certData: Buffer): void {
    try {
        fs.writeFileSync(certPath, certData);
    } catch (error) {
        const message = `Failed to save certificate: ${error}`;
        logs.error(message);
        throw new Error(message);
    }
}

export function isPEMFormat(input: string): boolean {
    const pemRegex = /^-----BEGIN [A-Z ]+-----\n([A-Za-z0-9+/=\n]+)-----END [A-Z ]+-----$/;
    return pemRegex.test(input);
}

export function generateRsaKeyPair(keySize: number = 4096): { publicKey: string, privateKey: string } {
    try {
        const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
            modulusLength: keySize,
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
        });
        return { publicKey, privateKey };
    } catch (error) {
        const message = `Failed to generate RSA key pair: ${error}`;
        logs.error(message);
        throw new Error(message);
    }
}

export function generateEcdsaKeyPair(curve: string = 'P-256'): { publicKey: string, privateKey: string } {
    try {
        const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
            namedCurve: curve,
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
        });
        return { publicKey, privateKey };
    } catch (error) {
        const message = `Failed to generate ECDSA key pair: ${error}`;
        logs.error(message);
        throw new Error(message);
    }
}

export function publicKeyToJWK(publicKeyPem: string, keyId: string): JWK {
    try {
        const publicKey = crypto.createPublicKey(publicKeyPem);
        const keyType = publicKey.asymmetricKeyType;

        if (keyType === 'rsa') {
            const jwk = crypto.createPublicKey(publicKeyPem).export({ format: 'jwk' });
            return {
                kty: 'RSA',
                n: jwk.n!,
                e: jwk.e!,
                kid: keyId,
                alg: 'PS512'
            };
        } else if (keyType === 'ec') {
            const jwk = crypto.createPublicKey(publicKeyPem).export({ format: 'jwk' });
            return {
                kty: 'EC',
                crv: jwk.crv!,
                x: jwk.x!,
                y: jwk.y!,
                kid: keyId,
                alg: 'ES256'
            };
        }
        throw new Error(`Unsupported key type: ${keyType}`);
    } catch (error) {
        const message = `Failed to convert public key to JWK: ${error}`;
        logs.error(message);
        throw new Error(message);
    }
}
