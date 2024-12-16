import { AxiosRequestConfig } from 'axios';

export interface SignedHttpsRequest {
    method: string;
    url: string;
    headers: {
        host: string;
        'content-digest'?: string;
        'signature-input'?: string;
        'signature'?: string;
        'x-certificate-bundle'?: string;
        [key: string]: string | undefined;
    };
}

export interface HttpsSignatureComponents {
    '@method': string;
    '@authority': string;
    '@target-uri': string;
    'content-digest': string;
    '@signature-params': string;
    [key: string]: string;
}

export interface SignedRequestMetadata {
    authority: string;
    method: string;
    targetUri: string;
    contentDigest?: string;
}

export interface ExtractedProperties {
    publicKeyPem: string;
    signature: string;
    signatureBase: string;
}

export interface IETFRequestParams {
    method: string;
    url: string;
    body: string;
    bearerToken?: string;
}

export interface IETFRequestResult {
    contentDigest: string;
    sigInput: string;
    certBase64: string;
    signature: string;
    authHeader: string;
}

export interface SignatureMetadata {
    keyId: string;
    algorithm: string;
    created: number;
}

export interface SignatureVerificationParams {
    publicKeyPem: string;
    signature: string;
    signatureBase: string;
}

export interface IETFRequestConfig extends AxiosRequestConfig {
    retries?: number;
    retryDelay?: number;
}