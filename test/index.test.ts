import * as fs from 'fs';
import * as path from 'path';
import { ISignRequestConfig, buildSigningParts, QueryParams } from '../src/sigv4';
import { expect } from 'chai';
import { parse as parseUrl } from 'url';

const TEST_ACCESS_KEY = 'AKIDEXAMPLE';
const TEST_SECRET = 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY';

describe('AWS Test Cases', () => {

    it('works', async () => {
        const dirs = [
            'get-header-value-trim',
            'get-unreserved',
            'get-utf8',
            'get-vanilla',
            'get-vanilla-empty-query-key',
            'get-vanilla-query',
            'post-header-key-case',
            'post-header-key-sort',
            'post-header-value-case',
            'post-vanilla',
            'post-vanilla-empty-query-value',
            'post-vanilla-query',
        ];

        for (let i = 0; i < dirs.length; i++) {
            const dir = dirs[i];
            const test = await loadTestData(path.join(__dirname, 'aws-test-cases', dir));
            const parts = buildSigningParts(test.config);
            expect(parts.authHeader, `${test.name} failed`).to.eq(test.authHeader);
        }
    });
});

//------------------

export interface ITestData {
    name: string;
    config: ISignRequestConfig;
    authHeader: string;
}

async function loadTestData(dirPath: string): Promise<ITestData> {
    const dirName = dirPath.split('/').pop();

    const config = await buildReqConfig(path.join(dirPath, dirName + '.req'));
    const authHeader = await readFile(path.join(dirPath, dirName + '.authz'));

    return {
        name: dirName,
        config,
        authHeader,
    };
}

async function buildReqConfig(filePath: string): Promise<ISignRequestConfig> {
    const rawReq = await readFile(filePath);
    const lines = rawReq.split('\n');
    const line1 = lines.shift();
    const [ method, pathAndQuery ] = line1.split(' ');
    const [ path, query ] = pathAndQuery.split('?');
    const url = parseUrl('http://dummy.com' + pathAndQuery);

    // query
    const params: QueryParams = {};
    if (url.query != null) {
        url.query.split('&').forEach(pair => {
            const [ name, value ] = pair.split('=');
            params[name] = value;
        });
    }

    // read headers
    const headers: any = {};
    let nextLine = lines.shift();
    while (nextLine != null && nextLine.length > 0) {
        const [ name, value ] = nextLine.split(':');
        headers[name] = value;
        nextLine = lines.shift();
    }

    return {
        method,
        path: url.pathname,
        params,
        headers,
        endpoint: 'http://example.amazonaws.com',
        region: 'us-east-1',
        serviceName: 'service',
        accessKey: TEST_ACCESS_KEY,
        secretKey: TEST_SECRET,
    }
}

function readFile(path: string): Promise<string> {
    return new Promise((resolve, reject) => {
        fs.readFile(path, (err, buffer) => {
            if (err) {
                reject(err);
            } else {
                resolve(buffer.toString());
            }
        });
    });
}
