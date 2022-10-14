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
