const assert = require('assert');
const express = require('express');
const request = require('supertest');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const session = require('express-session');

const format = require('..');

function testRequestBody (parser, contentType, body, expected, done) {
    const app = express();
    app.use(parser);
    app.post('/', (req, res, next) => {
        try { res.json(format(req, res)); } catch (err) { next(err); }
    });
    request(app)
        .post('/')
        .set('Content-Type', contentType)
        .send(body)
        .expect(200)
        .then(function (res) {
            const log = res.body;
            assert.deepStrictEqual(log.body, expected);
        })
        .then(done, done);
}

describe('format()', function () {
    it('should format GET request', function (done) {
        const app = express();

        app.use(cookieParser());
        app.use(session({ secret: 'test' }));

        app.get('/:param', (req, res) => {
            res.locals.v = 1;
            try { res.json(format(req, res)); } catch (err) { next(err); }
        });

        request(app)
            .get('/test?q=1')
            .set('Cookie', ['test=1'])
            .set('Referer', 'referer')
            .set('User-Agent', 'user agent')
            .expect(200)
            .then(function (res) {
                const log = res.body;
                assert.strictEqual(log.method, 'GET');
                assert.strictEqual(log.url, '/test?q=1');
                assert.strictEqual(log.path, '/test');
                assert.deepStrictEqual(log.query, { q: '1' });
                assert.deepStrictEqual(log.params, { param: 'test' });
                assert.deepStrictEqual(log.cookies, { test: '1' });
                assert.strictEqual(log.referer, 'referer');
                assert.strictEqual(log.userAgent, 'user agent');
                assert.strictEqual(log.headers['referer'], 'referer');
                assert.strictEqual(log.headers['user-agent'], 'user agent');
                assert.ok(log.session);
                assert.strictEqual(log.status, 200);
                assert.strictEqual(log.locals.v, 1);
                assert.strictEqual(log.responseHeaders['x-powered-by'], 'Express');
            })
            .then(done, done);
    });

    it('should include response headers', function (done) {
        const app = express();
        app.get('/', (req, res) => {
            res.sendStatus(204);
            try {
                const log = format(req, res);
                assert.strictEqual(log.responseHeaders['x-powered-by'], 'Express');
                done();
            } catch (err) {
                done(err);
            }
        });
        request(app)
            .get('/')
            .expect(204)
            .end(() => {});
    });

    it('should format POST request with JSON body', function (done) {
        testRequestBody(
            bodyParser.json(),
            'application/json',
            { test: true },
            { test: true },
            done);
    });

    it('should format POST request with text body', function (done) {
        testRequestBody(
            bodyParser.text(),
            'text/plain',
            'test',
            'test',
            done);
    });

    it('should format POST request with raw body', function (done) {
        testRequestBody(
            bodyParser.raw(),
            'application/octet-stream',
            '1',
            { data: [49], type: 'Buffer' },
            done);
    });

    it('should format POST request with urlencoded body', function (done) {
        testRequestBody(
            bodyParser.urlencoded({ extended: false }),
            'application/x-www-form-urlencoded',
            'test=1',
            { test: '1' },
            done);
    });
});
