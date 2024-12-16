import { URL } from 'url';
import { X509Certificate } from 'crypto';
import { CreateLogger } from '../utils';
import { HttpsSignatureComponents, ExtractedProperties } from './ietf-https-types';

const logs = CreateLogger();

type ProtocolPorts = {
    readonly [K in 'http:' | 'https:']: string;
};

const DEFAULT_PORTS: ProtocolPorts = {
    'http:': '80',
    'https:': '443'
};

export function ExtractPropertiesFromResponse(resp: {
    headers: {
        'x-certificate-bundle'?: string;
        'signature'?: string;
        'signature-input'?: string;
        'content-digest'?: string;
    };
    config: {
        url: string;
        method: string;
    };
}): ExtractedProperties {
    ValidateIETFResponse(resp);

    const serverCertificate = ParseX509CertFromIETFResponse(resp.headers['x-certificate-bundle']!);
    const x509 = new X509Certificate(serverCertificate);
    const serverPublicKeyPem = x509.publicKey.export({ type: 'spki', format: 'pem' }).toString();
    const signature = resp.headers['signature']!;
    const signatureBase = ParseCoveredContentFromIETFResponse(resp);

    return {
        publicKeyPem: serverPublicKeyPem,
        signature: signature,
        signatureBase: signatureBase
    };
}

export function ParseX509CertFromIETFResponse(serverCertificateBundle: string): Buffer {
    try {
        return Buffer.from(serverCertificateBundle, 'base64');
    } catch (error) {
        const message = `Error decoding the certificate bundle from response: ${error}`;
        logs.error(message);
        throw new Error(message);
    }
}

export function ParseCoveredContentFromIETFResponse(resp: {
    headers: {
        'signature-input'?: string;
        'content-digest'?: string;
    };
    config: {
        url: string;
        method: string;
    };
}): string {
    ValidateIETFResponse(resp);

    const signatureParam = resp.headers['signature-input']!.split('sig1=')[1];
    const contentDigest = resp.headers['content-digest']!;

    try {
        const parsedUrl = new URL(resp.config.url);
        const method = resp.config.method.toUpperCase();
        const defaultPort = parsedUrl.protocol === 'https:' ? DEFAULT_PORTS['https:'] : DEFAULT_PORTS['http:'];
        const port = parsedUrl.port || defaultPort;
        const authority = port === DEFAULT_PORTS['http:'] && parsedUrl.protocol === 'http:' ||
            port === DEFAULT_PORTS['https:'] && parsedUrl.protocol === 'https:' ?
            parsedUrl.hostname :
            `${parsedUrl.hostname}:${port}`;
        const targetUri = parsedUrl.pathname + parsedUrl.search;

        return CreateSignatureBaseFromCoveredContent({
            '@method': method,
            '@authority': authority,
            '@target-uri': targetUri,
            'content-digest': contentDigest,
            '@signature-params': signatureParam
        });
    } catch (error) {
        const message = `Error parsing URL or formatting content: ${error}`;
        logs.error(message);
        throw new Error(message);
    }
}

function ValidateIETFResponse(resp: {
    headers: {
        'x-certificate-bundle'?: string;
        'signature'?: string;
        'signature-input'?: string;
        'content-digest'?: string;
    };
}) {
    if (!resp.headers['x-certificate-bundle']) {
        logs.error('Server certificate bundle is missing');
        throw new Error('Server certificate bundle is missing');
    }
    if (!resp.headers['signature']) {
        logs.error('Response signature is missing');
        throw new Error('Response signature is missing');
    }
    if (!resp.headers['signature-input']) {
        logs.error('Signature input is missing');
        throw new Error('Signature input is missing');
    }
    if (!resp.headers['content-digest']) {
        logs.error('Content digest is missing');
        throw new Error('Content digest is missing');
    }
}

function CreateSignatureBaseFromCoveredContent(components: HttpsSignatureComponents): string {
    return Object.entries(components)
        .map(([key, value]) => `"${key}": ${key === '@signature-params' ? value : `${value}`}`)
        .join('\n');
}