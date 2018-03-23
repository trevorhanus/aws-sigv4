import { buildSigningParts, ISignRequestConfig, ISigningParts, Headers, QueryParams } from './sigv4';

// high-level api

export function sign(config: ISignRequestConfig): Headers {
    return buildSigningParts(config).headers;
}

export {
    ISignRequestConfig,
    Headers,
    QueryParams,
    ISigningParts,
}

// export low level api as well

export {
    buildSigningParts
}

export {
    buildCanonicalRequest,
    buildStringToSign,
    buildSigningKey,
    buildSignature,
    buildAuthorizationHeader,
} from './sigv4'
