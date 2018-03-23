import { enc, HmacSHA256, SHA256, WordArray } from 'crypto-js';

export function assertProps(config: any, props: any) {
    for (let prop of props) {
        if (typeof config[prop] === 'undefined') {
            throw `[SigV4]: missing config property '${prop}'`;
        }
    }
}

export function assertValue(config: any, prop: string, val: any) {
    if (config[prop] == null) {
        config[prop] = val
    }
}

export function hash(value: string): WordArray {
    return SHA256(value);
}

export function hexEncode(value: WordArray): string {
    return value.toString(enc.Hex);
}

export function hmac(key: string | WordArray, value: string): WordArray {
    return HmacSHA256(value, key, { asBytes: true });
}

export function fixedEncodeURIComponent(str: string): string {
    return encodeURIComponent(str).replace(/[!'()*]/g, (c) => {
        return '%' + c.charCodeAt(0).toString(16)
    });
}
