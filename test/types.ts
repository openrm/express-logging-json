import express from 'express';
import format, { mask } from '..';

const app = express();

app.use((req, res, next) => {
    res.on('finish', () => {
        const log = format(req, res, { maxBodyLen: 10_000 });
        mask(log, ['headers.authorization', 'invalid'], { placeholder: 'masked' });
        console.info(log);
    });
    next();
});

import { redact, redactString, secrets } from '..';

const masked: { a: string } = redact({ a: 'x' }, { auto: true, keys: ['b', /c/], values: [/d/], placeholder: '*' });
const text: string = redactString('text', { auto: true });
const secret: boolean = secrets.isSecretKey('password') && secrets.isSecretEntry('token', 'x');
const patterns: RegExp[] = secrets.valuePatterns();
format({} as express.Request, {} as express.Response, { mask: { fields: ['headers.cookie'], auto: true, keys: ['pin'] } });
