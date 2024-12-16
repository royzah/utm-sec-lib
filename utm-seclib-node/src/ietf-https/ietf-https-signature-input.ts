import { CreateLogger } from '../utils';
import { SignedHttpsRequest, SignedRequestMetadata, HttpsSignatureComponents, SignatureMetadata } from './ietf-https-types';

const logs = CreateLogger();

export function CreateSignatureInput(
    request: SignedHttpsRequest,
    keyId: string,
    algorithm: string
): string {
    if (!request || !request.headers.host) {
        logs.error('Invalid request: missing required fields');
        throw new Error('Invalid request: missing required fields');
    }

    if (!isSupportedMethod(request.method)) {
        logs.error(`Unsupported method: ${request.method}`);
        throw new Error(`Unsupported method: ${request.method}`);
    }

    const coveredContent = parseCoveredContentFromRequest(request);

    if (request.headers['content-digest']) {
        coveredContent.contentDigest = request.headers['content-digest'];
    }

    return parseSignatureInputFromCoveredContent(coveredContent, keyId, algorithm);
}

function parseSignatureInputFromCoveredContent(
    coveredContent: SignedRequestMetadata,
    keyId: string,
    algorithm: string
): string {
    const components = ['"@method"', '"@authority"', '"@target-uri"'];

    if (coveredContent.contentDigest) {
        components.push('"content-digest"');
    }

    const metadata = createSignatureInputMetadata({
        keyId,
        algorithm,
        created: getCurrentTimestamp()
    });

    return `sig1=(${components.join(' ')});${metadata}`;
}

function parseCoveredContentFromRequest(request: SignedHttpsRequest): SignedRequestMetadata {
    return {
        authority: request.headers.host,
        method: request.method,
        targetUri: request.url,
        contentDigest: undefined,
    };
}

function createSignatureInputMetadata(metadata: SignatureMetadata): string {
    return `created=${metadata.created};keyid="${metadata.keyId}";alg="${metadata.algorithm}"`;
}

function getCurrentTimestamp(): number {
    const millisecondsInSecond = 1000;
    return Math.floor(Date.now() / millisecondsInSecond);
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

export function ParseCoveredContentFromIETFRequest(req: SignedHttpsRequest): string {
    const signatureInput = req.headers['signature-input'];
    if (!signatureInput) {
        logs.error('Signature input not found in request headers');
        throw new Error('Signature input not found in request headers');
    }

    const signatureParam = signatureInput.split('sig1=')[1];
    const contentDigest = req.headers['content-digest'];
    if (!contentDigest) {
        logs.error('Content digest not found in request headers');
        throw new Error('Content digest not found in request headers');
    }

    const method = req.method;
    const authority = req.headers['host'];
    if (!authority) {
        logs.error('Host not found in request headers');
        throw new Error('Host not found in request headers');
    }

    const targetUri = req.url;

    const resultObject: HttpsSignatureComponents = {
        '@method': method,
        '@authority': authority,
        '@target-uri': targetUri,
        'content-digest': contentDigest,
        '@signature-params': signatureParam,
    };

    return Object.entries(resultObject)
        .map(([key, value]) => `"${key}": ${key === '@signature-params' ? value : `${value}`}`)
        .join('\n');
}
