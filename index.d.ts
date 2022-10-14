import http from 'http';
import express from 'express';

type MaskOptions = {
    placeholder?: string;
};

type LogOptions = {
    maxBodyLen?: number;
    mask?: MaskOptions & { fields?: string[] };
};

type RequestKeys = 'ip' | 'ips' | 'hostname' | 'protocol' | 'method' | 'path' | 'fresh' | 'subdomains' | 'xhr' | 'headers' | 'trailers' | 'query' | 'params';
type ResponseKeys = 'locals';

type Log = Pick<express.Request, RequestKeys> & Pick<express.Response, ResponseKeys> & {
    url: string;
    referer: string;
    userAgent: string;
    protocolVersion: typeof express.request.httpVersion;
    responseHeaders: http.OutgoingHttpHeaders;
    // TODO: annotate properties from third party libraries such as express-session, cookie-parser
};

declare function ExpressLoggingJson(req: express.Request, res: express.Response, options?: LogOptions): Log;

declare namespace ExpressLoggingJson {
    function format(req: express.Request, res: express.Response, options?: LogOptions): Log;
    function mask(obj: object, fields: string[], options?: MaskOptions): object;
}

export = ExpressLoggingJson;
