export {
    CreateIETFRequestParams,
    CreateIETFRequest,
    SendIETFRequest,
    ExtractPropertiesFromRequest,
} from './src/ietf-https/ietf-https-request';

export {
    ExtractPropertiesFromResponse,
} from './src/ietf-https/ietf-https-response';

export {
    VerifySignature,
} from './src/ietf-https/ietf-https-signature';

export {
    VerifyContentDigest
} from './src/ietf-https/ietf-https-content-digest';

export {
    CreateLogger as logger,
} from './src/utils';

export type {
    SignedHttpsRequest,
    HttpsSignatureComponents,
    SignedRequestMetadata,
    IETFRequestParams,
    IETFRequestResult,
    ExtractedProperties,
} from './src/ietf-https/ietf-https-types';