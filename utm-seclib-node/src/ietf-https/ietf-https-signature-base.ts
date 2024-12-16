import { CreateLogger } from '../utils';
import { SignedHttpsRequest, SignedRequestMetadata, SignatureMetadata } from './ietf-https-types';

const logs = CreateLogger();

export function CreateSignatureBase(
    request: SignedHttpsRequest,
    keyId: string,
    algorithm: string
): string {
    if (!request) {
        logs.error('Request cannot be null');
        throw new Error('Request cannot be null');
    }

    if (!request.headers.host || !request.method || !request.url) {
        logs.error('Invalid request: missing required fields');
        throw new Error('Invalid request: missing required fields');
    }

    if (!isSupportedMethod(request.method)) {
        logs.error(`Unsupported method: ${request.method}`);
        throw new Error(`Unsupported method: ${request.method}`);
    }

    checkSignatureEnvironmentVariablesSet(keyId, algorithm);

    const coveredContent = parseCoveredContentFromRequest(request);
    const contentDigestHeader = request.headers['content-digest'];

    if (contentDigestHeader) {
        coveredContent.contentDigest = contentDigestHeader;
    }

    return GetCoveredContentAsString(coveredContent, keyId, algorithm);
}

function checkSignatureEnvironmentVariablesSet(keyId: string, algorithm: string): void {
    if (!keyId) {
        logs.error('PKI_KEY_ID environment variable must be set');
        throw new Error('PKI_KEY_ID environment variable must be set');
    }

    if (!algorithm) {
        logs.error('PKI_SIGNING_ALGORITHM environment variable must be set');
        throw new Error('PKI_SIGNING_ALGORITHM environment variable must be set');
    }
}

function parseCoveredContentFromRequest(request: SignedHttpsRequest): SignedRequestMetadata {
    return {
        authority: request.headers.host,
        method: request.method,
        targetUri: request.url,
        contentDigest: undefined,
    };
}

export function GetCoveredContentAsString(
    content: SignedRequestMetadata,
    keyId: string,
    algorithm: string
): string {
    const contentDigestAttr = content.contentDigest
        ? `"content-digest": ${content.contentDigest}\n`
        : '';

    const signatureInputBase = [
        `"@method": ${content.method}`,
        `"@authority": ${content.authority}`,
        `"@target-uri": ${content.targetUri}`,
        contentDigestAttr.trim()
    ].filter(Boolean).join('\n') + '\n';

    const signatureParams = getSignatureParamsAsString(signatureInputBase);
    const metadata = createSignatureInputMetadata({ keyId, algorithm, created: getCurrentTimestamp() });

    return `${signatureInputBase}${signatureParams}${metadata}`;
}

function getSignatureParamsAsString(coveredContent: string): string {
    const sigParams = coveredContent.split('\n');
    const parameters = getSpacedParameters(sigParams);
    return `"@signature-params": (${parameters});`;
}

function createSignatureInputMetadata(metadata: SignatureMetadata): string {
    return `created=${metadata.created};keyid="${metadata.keyId}";alg="${metadata.algorithm}"`;
}

function getSpacedParameters(sigParams: string[]): string {
    return sigParams
        .filter(param => param.trim())
        .map(paramLine => paramLine.split(':')[0])
        .filter(param => param)
        .map((param, index, array) => `${param}${index < array.length - 1 ? ' ' : ''}`)
        .join('');
}

function getCurrentTimestamp(): number {
    const millisecondsInSecond = 1000;
    return Math.floor(Date.now() / millisecondsInSecond);
}

export function GetJsonBytesFromString(jsonStr: string): Buffer {
    if (!jsonStr) {
        logs.error('JSON string cannot be empty');
        throw new Error('JSON string cannot be empty');
    }

    try {
        JSON.parse(jsonStr);
        return Buffer.from(jsonStr);
    } catch (error) {
        const message = `Invalid JSON string: ${error}`;
        logs.error(message);
        throw new Error(message);
    }
}

export function SanitizeJsonString(jsonStr: string): string {
    if (!jsonStr) {
        logs.error('JSON string cannot be empty');
        throw new Error('JSON string cannot be empty');
    }

    try {
        const jsonObject = JSON.parse(jsonStr);
        return JSON.stringify(jsonObject);
    } catch (error) {
        const message = `Invalid JSON string: ${error}`;
        logs.error(message);
        throw new Error(message);
    }
}

function isSupportedMethod(method: string): boolean {
    const supportedMethods = [
        'GET',
        'POST',
        'PUT',
        'DELETE',
        'PATCH',
        'OPTIONS',
        'HEAD',
    ] as const;
    return supportedMethods.includes(method as typeof supportedMethods[number]);
}