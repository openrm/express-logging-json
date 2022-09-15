import express from 'express'

export function mask(obj: object, fields: Array<string>, options?: object): void;

/**
 * @TODO: Add additional properties
 */
type Log = {
    ip: string
    protocol: string
    method: string
    url: string
    referer: string
    userAgent: string
}

export function format(req: express.Request, res: express.Response, options?: object): Log;
