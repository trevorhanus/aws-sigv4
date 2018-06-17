import { WordArray } from 'crypto-js';
import * as url from 'url';
import { assertProps, assertValue, hash, hexEncode, hmac, fixedEncodeURIComponent } from './utils';

export type Headers = { [name: string]: string };
export type QueryParams = { [name: string]: string };

export interface ISignRequestConfig {
    method: string;
    endpoint: string;
    path: string;
    headers?: Headers;
    params?: QueryParams;
    data?: any;

    region: string;
    accessKey: string;
    secretKey: string;
    sessionToken?: string;
    serviceName?: string; // default 'execute-api'
}

const AWS_SHA_256           = 'AWS4-HMAC-SHA256';
const AWS4_REQUEST          = 'aws4_request';
const AWS4                  = 'AWS4';
const X_AMZ_DATE            = 'x-amz-date';
const X_AMZ_SECURITY_TOKEN  = 'x-amz-security-token';
const AUTHORIZATION         = 'Authorization';
const HOST                  = 'Host';

export interface ISigningParts {
    config: ISignRequestConfig,
    headers: Headers,
    authHeader: string;
    signature: string;
    canonicalRequest: string;
    stringToSign: string;
}

export function buildSigningParts(config: ISignRequestConfig): ISigningParts {

    assertProps(config, ['method', 'path', 'region', 'endpoint', 'accessKey', 'secretKey']);
    assertValue(config, 'headers', {});
    assertValue(config, 'params', {});
    assertValue(config, 'serviceName', 'execute-api');

    let datetime = null;
    const passedDateHeader = Object.keys(config.headers).find(val => val.toLowerCase() === X_AMZ_DATE);
    if (passedDateHeader != null) {
        datetime = config.headers[passedDateHeader];
    } else {
        datetime = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z').replace(/[:\-]|\.\d{3}/g, '');
        config.headers[X_AMZ_DATE] = datetime;
    }

    const path = getPath(config.endpoint, config.path);

    config.headers[HOST] = hostname(config.endpoint);

    if (config.sessionToken != null) {
        config.headers[X_AMZ_SECURITY_TOKEN] = config.sessionToken;
    }

    config.data = config.data != null ? JSON.stringify(config.data) : '';

    /* Perform SigV4 steps */
    const canonicalRequest = buildCanonicalRequest(config.method, path, config.headers, config.params, config.data);
    const credentialScope = buildCredentialScope(datetime, config.region, config.serviceName);
    const stringToSign = buildStringToSign(datetime, credentialScope, canonicalRequest);
    const signingKey = buildSigningKey(config.secretKey, datetime, config.region, config.serviceName);
    const signature = buildSignature(signingKey, stringToSign);
    const authHeader = buildAuthorizationHeader(config.accessKey, credentialScope, config.headers, signature);
    config.headers[AUTHORIZATION] = authHeader;

    return {
        config,
        headers: config.headers,
        authHeader,
        signature,
        stringToSign,
        canonicalRequest,
    };
}

// Canonical Request
// ------------------------------------

export function buildCanonicalRequest(method: string, path: string, headers: Headers, queryParams: QueryParams = {}, payload: string = ''): string {
    return  method.toUpperCase() + '\n' +
        buildCanonicalUri(path) + '\n' +
        buildCanonicalQueryString(queryParams) + '\n' +
        buildCanonicalHeaders(headers) + '\n' +
        buildCanonicalSignedHeaders(headers) + '\n' +
        buildHashedPayload(payload);
}

function buildCanonicalUri(path: string): string {
    const p = path == null || path === '' ? '/' : path;
    return encodeURI(p);
}

function buildCanonicalQueryString(queryParams: QueryParams): string {
    if (Object.keys(queryParams).length < 1) return '';

    const sorted = Object.keys(queryParams).map(name => {
        return {
            name,
            value: queryParams[name],
        }
    }).sort((a, b) => {
        if (a.name === b.name) {
            return a.value < b.value ? -1 : 1;
        } else {
            return a.name < b.name ? -1 : 1;
        }
    });

    const params = sorted.map(param => {
        return `${param.name}=${fixedEncodeURIComponent(param.value)}`;
    });

    return params.join('&');
}

function buildCanonicalHeaders(headers: Headers): string {
    const canonicalHeaders = Object.keys(headers).map(name => {
        return {
            oName: name,
            name: name.toLowerCase(),
            value: headers[name],
        };
    }).sort((a, b) => {
        if (a.oName === b.oName) {
            return a.value < b.value ? -1 : 1;
        } else {
            return a.oName < b.oName ? -1 : 1;
        }
    });

    return canonicalHeaders.reduce((prev, curr) => {
        return prev + curr.name + ':' + curr.value.trim().replace(/\s+/g,' ') + '\n';
    }, '');
}

function buildCanonicalSignedHeaders(headers: Headers): string {
    return Object.keys(headers).map(name => name.toLowerCase()).sort().join(';');
}

function buildHashedPayload(payload: string): string {
    return hexEncode(hash(payload)).toLowerCase()
}

// String to Sign
// ------------------------------------

export function buildStringToSign(datetime: string, credentialScope: string, canonicalRequest: string): string {
    return  AWS_SHA_256 + '\n' +
        datetime + '\n' +
        credentialScope + '\n' +
        hashCanonicalRequest(canonicalRequest);
}

function buildCredentialScope(datetime: string, region: string, service: string): string {
    return `${datetime.substr(0, 8)}/${region}/${service}/${AWS4_REQUEST}`;
}

function hashCanonicalRequest(request: string): string {
    return hexEncode(hash(request)).toLowerCase();
}

// Signing Key
// ------------------------------------

export function buildSigningKey(secretKey: string, datetime: string, region: string, service: string): WordArray {
    const kDate = hmac(AWS4 + secretKey, datetime.substr(0, 8));
    const kRegion = hmac(kDate, region);
    const kService = hmac(kRegion, service);
    return hmac(kService, AWS4_REQUEST);
}

// Signature
// ------------------------------------

export function buildSignature(key: WordArray, stringToSign: string): string {
    return hexEncode(hmac(key, stringToSign));
}

export function buildAuthorizationHeader(accessKey: string, credentialScope: string, headers: Headers, signature: string): string {
    return AWS_SHA_256 + ' Credential=' + accessKey + '/' + credentialScope + ', SignedHeaders=' +
        buildCanonicalSignedHeaders(headers) + ', Signature=' + signature;
}

function hostname(endpoint: string): string {
    const site = url.parse(endpoint);
    return site.hostname;
}

function getPath(endpoint: string, path: string): string {
    const u = url.parse(endpoint + path);
    return u.pathname;
}
