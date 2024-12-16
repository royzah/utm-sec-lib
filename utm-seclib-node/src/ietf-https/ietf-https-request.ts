import { URL } from 'url';
import axios, { AxiosResponse, AxiosError } from 'axios';
import { CreateSignatureInput, ParseCoveredContentFromIETFRequest } from './ietf-https-signature-input';
import { CreateSignatureBase } from './ietf-https-signature-base';
import { CreateContentDigest } from './ietf-https-content-digest';
import { CreateSignature } from './ietf-https-signature';
import { CreateCertificateBundle } from '../ussp-pki/pki';
import { X509Certificate } from 'crypto';
import { CreateLogger } from '../utils';
import {
    SignedHttpsRequest,
    ExtractedProperties,
    IETFRequestParams,
    IETFRequestResult,
    IETFRequestConfig,
} from './ietf-https-types';

const logs = CreateLogger();

export function CreateIETFRequestParams(
    method: string,
    url: string,
    body: string,
    bearerToken?: string
): IETFRequestParams {
    return { method, url, body, bearerToken };
}

export function CreateIETFRequest(
    ietfRequestParams: IETFRequestParams,
    privateKey: string,
    clientCertPath: string,
    keyId: string,
    algorithm: string
): IETFRequestResult {
    try {
        const { method, url, body, bearerToken } = ietfRequestParams;

        if (!method) {
            throw new Error('method is required');
        }
        if (!isSupportedMethod(method)) {
            throw new Error('unsupported method');
        }

        try {
            const parsedUrl = new URL(url);
            if (!parsedUrl.host) {
                throw new Error('invalid URL');
            }
        } catch (error) {
            const message = error instanceof Error ? error.message : 'Unknown error';
            throw new Error(`invalid URL: ${message}`);
        }

        if (body && !isValidJson(body)) {
            throw new Error('body is not valid JSON');
        }

        const contentDigest = CreateContentDigest(body);
        const parsedUrl = new URL(url);
        const targetURI = parsedUrl.pathname + parsedUrl.search;
        const authority = parsedUrl.host;

        const request: SignedHttpsRequest = {
            method,
            url: targetURI,
            headers: {
                host: authority,
                'content-type': 'application/json',
                'content-digest': contentDigest,
                'accept': 'application/json',
            },
        };

        const sigInput = createAndValidateSignatureInput(request, keyId, algorithm);
        const signatureBase = createAndValidateSignatureBase(request, keyId, algorithm);
        const signBase = Buffer.from(signatureBase, 'utf-8');
        const certBase64 = createAndValidateCertBundle(clientCertPath);
        const signature = createAndValidateSignature(signBase, privateKey);
        const authHeader = `Bearer ${bearerToken || process.env.BEARER_TOKEN}`;

        return {
            contentDigest,
            sigInput,
            certBase64,
            signature,
            authHeader,
        };
    } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        logs.error('IETF Request creation failed:', message);
        throw new Error(message);
    }
}

function createAndValidateSignatureInput(
    request: SignedHttpsRequest,
    keyId: string,
    algorithm: string
): string {
    const sigInput = CreateSignatureInput(request, keyId, algorithm);
    if (!sigInput) {
        throw new Error('Failed to create Signature-Input');
    }
    return sigInput;
}

function createAndValidateSignatureBase(
    request: SignedHttpsRequest,
    keyId: string,
    algorithm: string
): string {
    const signatureBase = CreateSignatureBase(request, keyId, algorithm);
    if (!signatureBase) {
        throw new Error('Failed to create Signature Base');
    }
    return signatureBase;
}

function createAndValidateCertBundle(clientCertPath: string): string {
    const certBase64 = CreateCertificateBundle(clientCertPath);
    if (!certBase64) {
        throw new Error('Failed to create Certificate Bundle');
    }
    return certBase64;
}

function createAndValidateSignature(signBase: Buffer, privateKey: string): string {
    const signature = CreateSignature(signBase, privateKey);
    if (!signature) {
        throw new Error('Failed to create signature');
    }
    return signature;
}

function isValidJson(json: string): boolean {
    try {
        JSON.parse(json);
        return true;
    } catch {
        return false;
    }
}

export async function SendIETFRequest<T = unknown>(
    url: string,
    body: unknown,
    headers: Record<string, string>,
    config: IETFRequestConfig = {}
): Promise<AxiosResponse<T>> {
    const {
        method = 'POST',
        timeout = 5000,
        retries = 3,
        retryDelay = 1000,
        ...restConfig
    } = config;
  
    const requiredHeaders = [
        'content-type',
        'content-digest',
        'signature',
        'signature-input',
        'x-certificate-bundle'
    ];
  
    const missingHeaders = requiredHeaders.filter(header => !headers[header]);
    if (missingHeaders.length > 0) {
        throw new Error(`Missing required headers: ${missingHeaders.join(', ')}`);
    }
  
    const makeRequest = async (attempt: number): Promise<AxiosResponse<T>> => {
        try {
            const response = await axios.request<T>({
                method,
                url,
                data: body,
                headers,
                timeout,
                ...restConfig
            });
  
            return response;
        } catch (error) {
            const axiosError = error as AxiosError;
  
            // Don't retry on certain status codes
            if (axiosError.response?.status && [400, 401, 403, 404].includes(axiosError.response.status)) {
                throw error;
            }
  
            if (attempt < retries) {
                logs.warn(`Request attempt ${attempt} failed, retrying in ${retryDelay}ms...`);
                await new Promise(resolve => setTimeout(resolve, retryDelay));
                return makeRequest(attempt + 1);
            }
  
            let message = 'Unknown error';
            if (
                axiosError.response?.data &&
          typeof axiosError.response.data === 'object' &&
          'error' in axiosError.response.data
            ) {
                const errorData = axiosError.response.data as { error: string };
                message = errorData.error;
            } else if (axiosError.message) {
                message = axiosError.message;
            }
  
            logs.error('Failed to send IETF request:', {
                attempt,
                error: message,
                status: axiosError.response?.status,
                url
            });
  
            throw new Error(message);
        }
    };
  
    return makeRequest(1);
}

export function getBase64CertFromRequest(certBundle: string): string {
    try {
        return Buffer.from(certBundle, 'base64').toString('ascii');
    } catch (error) {
        const message = `Error decoding the certificate bundle from request: ${error instanceof Error ? error.message : String(error)}`;
        logs.error(message);
        throw new Error(message);
    }
}

export function ExtractPropertiesFromRequest(
    req: SignedHttpsRequest
): ExtractedProperties {
    if (!req.headers) {
        throw new Error('Request validation failed: Headers are missing from the request.');
    }

    const signature = req.headers['signature'];
    const certBundle = req.headers['x-certificate-bundle'];

    if (!signature) {
        throw new Error('Request validation failed: Missing required header "signature".');
    }

    if (!certBundle) {
        throw new Error('Request validation failed: Missing required header "x-certificate-bundle".');
    }

    const signatureMatch = signature.match(/^sig1=\:(.+)\:$/);

    if (!signatureMatch || signatureMatch.length < 2) {
        throw new Error('Request validation failed: "signature" header has an invalid format.');
    }

    const signatureValue = signatureMatch[1];

    // Decode the certificate bundle from Base64
    let derBuffer: Buffer;
    try {
        derBuffer = Buffer.from(certBundle, 'base64');
    } catch (error) {
        throw new Error('Request validation failed: "x-certificate-bundle" header contains invalid Base64 encoding. ' + error);
    }

    // Parse the X.509 certificate
    let x509: X509Certificate;
    try {
        x509 = new X509Certificate(derBuffer);
    } catch (error) {
        throw new Error('Request validation failed: "x-certificate-bundle" header contains an invalid DER-encoded certificate. ' + error);
    }

    // Export the public key in PEM format
    let clientPublicKeyPem: string;
    try {
        clientPublicKeyPem = x509.publicKey.export({ type: 'spki', format: 'pem' }).toString();
    } catch (error) {
        throw new Error('Request validation failed: Unable to export the public key from the provided certificate. ' + error);
    }

    return {
        publicKeyPem: clientPublicKeyPem,
        signature: signatureValue,
        signatureBase: ParseCoveredContentFromIETFRequest(req)
    };
}

function isSupportedMethod(method: string): boolean {
    const supportedMethods = ['GET', 'POST', 'PUT', 'PATCH'];
    return supportedMethods.includes(method.toUpperCase());
}