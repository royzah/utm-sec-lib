import { SignDataWithPrivateKey, VerifyWithPublicKey } from '../ussp-pki/pki';
import { CreateLogger } from '../utils';
import { SignatureVerificationParams } from './ietf-https-types';

const logs = CreateLogger();

export function CreateSignature(signatureBase: Buffer, privateKey: string): string {
    validateSignatureCreationParams(signatureBase, privateKey);

    try {
        const signature = SignDataWithPrivateKey(privateKey, signatureBase);
        return formatSignature(signature);
    } catch (error) {
        const message = `Failed to create signature: ${error}`;
        logs.error(message);
        throw new Error(message);
    }
}

export function VerifySignature(
    publicKeyPem: string,
    signature: string,
    signatureBase: string
): boolean {
    validateSignatureVerificationParams({ publicKeyPem, signature, signatureBase });
    ValidateSignatureBase(signatureBase);

    try {
        return VerifyWithPublicKey(publicKeyPem, signature, signatureBase);
    } catch (error) {
        const message = error instanceof Error ? error.message : 'Unknown error verifying signature';
        logs.error(message);
        throw new Error(message);
    }
}

function validateSignatureCreationParams(
    signatureBase: Buffer,
    privateKey: string | undefined
): void {
    if (!privateKey?.trim()) {
        logs.error('Private key cannot be null or empty');
        throw new Error('Private key cannot be null or empty');
    }

    if (!signatureBase?.length) {
        logs.error('Signature base cannot be empty');
        throw new Error('Signature base cannot be empty');
    }
}

function validateSignatureVerificationParams(params: SignatureVerificationParams): void {
    if (!params.publicKeyPem?.trim()) {
        logs.error('Public key cannot be null or empty');
        throw new Error('Public key cannot be null or empty');
    }

    if (!params.signature?.trim()) {
        logs.error('Signature cannot be null or empty');
        throw new Error('Signature cannot be null or empty');
    }

    if (!params.signatureBase?.trim()) {
        logs.error('Signature base cannot be null or empty');
        throw new Error('Signature base cannot be null or empty');
    }
}

export function ValidateSignatureBase(signatureBase: string): void {
    if (!signatureBase?.trim()) {
        logs.error('Signature base cannot be empty');
        throw new Error('Signature base cannot be empty');
    }

    if ((signatureBase.match(/"@signature-params": \(/g) || []).length !== 1) {
        throw new Error('Signature input does not contain signature params');
    }

    const paramsMatch = signatureBase.match(/"@signature-params": \((".+")\)/);
    if (!paramsMatch?.[1]) {
        throw new Error('Signature input does not contain signature params');
    }

    const expectedParameters = paramsMatch[1].split(' ');
    for (const param of expectedParameters) {
        const paramRegex = new RegExp(`${param}:( .+)\\n`);
        if (!paramRegex.test(signatureBase)) {
            throw new Error(`Signature parameter ${param} does not have a valid value: "<sig param name>": <value>"`);
        }
    }

    const metadataRegex = /created=\d+;keyid="\S+";alg="\S+"/;
    if (!metadataRegex.test(signatureBase)) {
        throw new Error('Signature input does not contain signature metadata');
    }
}

function formatSignature(signature: string): string {
    return `sig1=:${signature}:`;
}