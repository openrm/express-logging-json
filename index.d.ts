import http from 'http';
import express from 'express';

interface MaskOptions {
    placeholder?: string;
}

interface RedactOptions extends MaskOptions {
    /** Names whose values are replaced, at any depth: strings (case insensitive) or regular expressions */
    keys?: Array<string | RegExp>;
    /** Regular expressions whose matches are replaced in every string */
    values?: RegExp[];
    /** Also use the names and shapes of `secrets`: what most secrets look like */
    auto?: boolean;
    /**
     * With `auto`, names to leave alone although they sound secret, such as ids in an `x-token-user` header.
     * Strings (case insensitive) or regular expressions. Secret shapes inside them are still masked.
     */
    except?: Array<string | RegExp>;
    /**
     * Paths to leave out of the copy, such as 'headers.accept', or regular expressions tested against
     * them, such as /^headers\.sec-/. The items of an array share the path of the array
     */
    omit?: Array<string | RegExp>;
}

interface LogOptions {
    maxBodyLen?: number;
    /**
     * Parts of the log to leave out, as paths ('trailers', 'headers.accept') or regular expressions tested
     * against them. A log refers to a lot of what a request carries, and this is how to log less of it
     */
    omit?: Array<string | RegExp>;
    /** `fields` are paths such as 'headers.authorization'. Masking works on a copy, never on the request */
    mask?: Omit<RedactOptions, 'omit'> & { fields?: string[] };
}

type RequestKeys = 'ip' | 'ips' | 'hostname' | 'protocol' | 'method' | 'path' | 'fresh' | 'subdomains' | 'xhr' | 'headers' | 'trailers' | 'query' | 'params';
type ResponseKeys = 'locals';

interface Log extends Pick<express.Request, RequestKeys>, Pick<express.Response, ResponseKeys> {
    url: string;
    referer: string;
    userAgent: string;
    protocolVersion: typeof express.request.httpVersion;
    responseHeaders: http.OutgoingHttpHeaders;
    // TODO: annotate properties from third party libraries such as express-session, cookie-parser
}

declare function ExpressLoggingJson(req: express.Request, res: express.Response, options?: LogOptions): Log;

declare namespace ExpressLoggingJson {
    function format(req: express.Request, res: express.Response, options?: LogOptions): Log;
    /** Replaces the values at the given paths, in `obj` itself */
    function mask(obj: object, fields: string[], options?: MaskOptions): void;
    /** A copy of `value` with the secrets masked wherever they are; `value` is not changed */
    function redact<T>(value: T, options?: RedactOptions): T;
    /** Masks the secret shapes in a text; only `values` and `auto` apply */
    function redactString(text: string, options?: Omit<RedactOptions, 'keys'>): string;
    const secrets: {
        /** Whether the name of a key says it holds a secret, such as 'password' or 'x-api-key' */
        isSecretKey(key: string): boolean;
        /** As isSecretKey, for a key with its value: flags, nulls and cookie settings have nothing to hide */
        isSecretEntry(key: string, value: unknown): boolean;
        /** The regular expressions of the secret shapes `auto` looks for */
        valuePatterns(): RegExp[];
    };
}

export = ExpressLoggingJson;
