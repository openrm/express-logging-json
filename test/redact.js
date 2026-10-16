const assert = require('assert');
const { redact, redactString, secrets } = require('..');

// Not real credentials: shaped like them
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
const jwt = `${b64({ alg: 'HS256', typ: 'JWT' })}.${b64({ sub: 'user-1', exp: 1 })}.c2lnbmF0dXJlLXNpZ25hdHVyZQ`;

describe('redact()', function () {
    it('should return falsy and primitive values as they are', function () {
        for (const v of [0, false, null, undefined, 1, 'text']) assert.strictEqual(redact(v, { auto: true }), v);
    });

    it('should not change the original', function () {
        const original = { headers: { authorization: `Bearer ${jwt}` }, list: [{ password: 'x' }] };
        const copy = JSON.parse(JSON.stringify(original));
        const masked = redact(original, { auto: true });
        assert.deepStrictEqual(original, copy);
        assert.notStrictEqual(masked, original);
        assert.notStrictEqual(masked.headers, original.headers);
    });

    it('should do nothing but copy without options', function () {
        const o = { a: 1, password: 'x', b: { c: `Bearer ${jwt}` } };
        assert.deepStrictEqual(redact(o), o);
    });

    describe('keys', function () {
        it('should mask named keys at any depth, ignoring case', function () {
            const masked = redact({ A: 1, nested: { list: [{ Secret: 'x', ok: 1 }] } }, { keys: ['secret', 'a'] });
            assert.deepStrictEqual(masked, { A: '[Filtered]', nested: { list: [{ Secret: '[Filtered]', ok: 1 }] } });
        });

        it('should mask keys matching a regular expression, even a global one', function () {
            const masked = redact({ x1: 1, x2: 2, y: 3 }, { keys: [/^x\d$/g] });
            assert.deepStrictEqual(masked, { x1: '[Filtered]', x2: '[Filtered]', y: 3 });
        });

        it('should mask whole objects under a masked key', function () {
            assert.deepStrictEqual(redact({ tokens: { a: 1 } }, { keys: ['tokens'] }), { tokens: '[Filtered]' });
        });

        it('should use the placeholder given, null included', function () {
            assert.deepStrictEqual(redact({ a: 1 }, { keys: ['a'], placeholder: null }), { a: null });
            assert.deepStrictEqual(redact({ a: 1 }, { keys: ['a'], placeholder: '***' }), { a: '***' });
        });
    });

    describe('values', function () {
        it('should replace matches within strings, in every string', function () {
            const masked = redact({ a: 'id=123456 x', b: ['y 654321'] }, { values: [/\d{6}/] });
            assert.deepStrictEqual(masked, { a: 'id=[Filtered] x', b: ['y [Filtered]'] });
        });

        it('should not be bothered by regular expressions with state', function () {
            const values = [/\d{3}/g];
            assert.strictEqual(redactString('123 456 789', { values }), '[Filtered] [Filtered] [Filtered]');
            assert.strictEqual(redactString('123 456 789', { values }), '[Filtered] [Filtered] [Filtered]');
        });
    });

    describe('auto', function () {
        const mask = (o) => redact(o, { auto: true });

        it('should mask keys that name secrets, whatever their style', function () {
            const masked = mask({
                password: 'a',
                'x-auth-token': 'b',
                csrfSecret: 'c',
                'set-cookie': ['d'],
                Authorization: 'e',
                API_KEY: 'f',
                apiKey: 'g',
                app_session_id: 'h',
                refreshToken: 'i',
                signature: 'j',
                refresh_jwt: 'k',
                'x-csrf-token': 'l'
            });
            for (const [key, value] of Object.entries(masked)) assert.strictEqual(value, '[Filtered]', key);
        });

        it('should leave alone what has nothing to hide', function () {
            const o = {
                'access-control-allow-credentials': 'true',
                token: false,
                password: null,
                session: { cookie: { httpOnly: true, path: '/', sameSite: true }, views: 2 }
            };
            assert.deepStrictEqual(mask(o), o);
        });

        it('should mask the Cookie headers and nothing else named cookie', function () {
            const masked = mask({ cookie: 'a=1; b=2', 'Set-Cookie': ['a=1', 'b=2'], cookies: { theme: 'dark' } });
            assert.deepStrictEqual(masked, { cookie: '[Filtered]', 'Set-Cookie': '[Filtered]', cookies: { theme: 'dark' } });
        });

        it('should leave alone names that merely contain such letters', function () {
            const o = {
                passport: 1, author: 2, tokenizer: 3, bypass: 4, compass: 5, sessions: 6, cookies: { _ga: 'x' },
                keyboard: 7, monkey: 8, id: 9, session: { views: 1 }
            };
            assert.deepStrictEqual(mask(o), o);
        });

        it('should mask secret shapes in any key and keep the rest readable', function () {
            const masked = mask({
                note: `Authorization: Bearer ${jwt} end`,
                other: `jwt ${jwt}`,
                url: '/file?name=a&signature=abc123def456&x=1',
                link: 'https://h/p?access_token=zzz999yyy888#frag',
                aws: 'key AKIAABCDEFGHIJKLMNOP end',
                stripe: 'sk_live_abcdefghijklmnop1234',
                pem: '-----BEGIN PRIVATE KEY-----\nMIIabc\n-----END PRIVATE KEY-----'
            });
            assert.strictEqual(masked.note, 'Authorization: Bearer [Filtered] end');
            assert.strictEqual(masked.other, 'jwt [Filtered]');
            assert.strictEqual(masked.url, '/file?name=a&signature=[Filtered]&x=1');
            assert.strictEqual(masked.link, 'https://h/p?access_token=[Filtered]#frag');
            assert.strictEqual(masked.aws, 'key [Filtered] end');
            assert.strictEqual(masked.stripe, '[Filtered]');
            assert.strictEqual(masked.pem, '[Filtered]');
        });

        it('should not mistake ids and hashes for secrets', function () {
            const o = {
                file: '/files/d41d8cd98f00b204e9800998ecf8427e.png',
                uuid: '00000000-0000-4000-8000-000000000000',
                sha: '0123456789abcdef0123456789abcdef01234567',
                query: '?app_id=00000000-0000-4000-8000-000000000000&page=2&key=abc'
            };
            assert.deepStrictEqual(mask(o), o);
        });

        it('should combine with keys and values', function () {
            const masked = redact({ pin: 1, text: 'order 123456', password: 'x' }, { auto: true, keys: ['pin'], values: [/\d{6}/] });
            assert.deepStrictEqual(masked, { pin: '[Filtered]', text: 'order [Filtered]', password: '[Filtered]' });
        });
    });

    describe('except', function () {
        const options = { auto: true, except: ['x-token-user', /^x-token-org/i] };

        it('should leave the excepted names alone, by string or regular expression', function () {
            const o = { 'X-Token-User': '42', 'x-token-organization': '7', 'x-token-other': 'abc123' };
            assert.deepStrictEqual(redact(o, options), { 'X-Token-User': '42', 'x-token-organization': '7', 'x-token-other': '[Filtered]' });
        });

        it('should leave the excepted names alone at any depth', function () {
            const o = { headers: [{ 'x-token-user': '42', password: 'x' }] };
            assert.deepStrictEqual(redact(o, options), { headers: [{ 'x-token-user': '42', password: '[Filtered]' }] });
        });

        it('should still mask secret shapes in what is excepted', function () {
            const masked = redact({ 'x-token-user': `Bearer ${jwt}`, 'x-token-organization': jwt, nested: { 'x-token-user': `?sig=abcdef12` } }, options);
            assert.deepStrictEqual(masked, { 'x-token-user': 'Bearer [Filtered]', 'x-token-organization': '[Filtered]', nested: { 'x-token-user': '?sig=[Filtered]' } });
        });

        it('should let keys win over except', function () {
            const masked = redact({ 'x-token-user': '42' }, { auto: true, except: ['x-token-user'], keys: ['x-token-user'] });
            assert.deepStrictEqual(masked, { 'x-token-user': '[Filtered]' });
        });

        it('should not be bothered by regular expressions with state', function () {
            const o = { 'x-token-a': '1', 'x-token-b': '2', 'x-token-c': '3' };
            assert.deepStrictEqual(redact(o, { auto: true, except: [/^x-token-/g] }), o);
        });

        it('should have no effect without auto', function () {
            assert.deepStrictEqual(redact({ a: 1, password: 'x' }, { except: ['password'] }), { a: 1, password: 'x' });
        });
    });

    describe('objects', function () {
        it('should survive circular references', function () {
            const o = { password: 'x', name: 'a' };
            o.self = o;
            const masked = redact(o, { auto: true });
            assert.strictEqual(masked.password, '[Filtered]');
            assert.strictEqual(masked.self, masked);
        });

        it('should handle objects without a prototype, class instances and arrays', function () {
            const bare = Object.create(null);
            bare.token = 'x';
            bare.a = 1;
            class Session { constructor () { this.csrfSecret = 'x'; this.views = 2; } }
            const masked = redact({ bare, session: new Session(), list: [[{ token: 'y' }]] }, { auto: true });
            assert.deepStrictEqual(masked, {
                bare: { token: '[Filtered]', a: 1 },
                session: { csrfSecret: '[Filtered]', views: 2 },
                list: [[{ token: '[Filtered]' }]]
            });
        });

        it('should serialise through toJSON, and keep dates, buffers and errors', function () {
            const date = new Date(0), buffer = Buffer.from('x'), error = new Error('e');
            const id = { toJSON: () => 'id-1' };
            const masked = redact({ date, buffer, error, id, doc: { toJSON: () => ({ password: 'x', n: 1 }) } }, { auto: true });
            assert.strictEqual(masked.date, date);
            assert.strictEqual(masked.buffer, buffer);
            assert.strictEqual(masked.error, error);
            assert.strictEqual(masked.id, 'id-1');
            assert.deepStrictEqual(masked.doc, { password: '[Filtered]', n: 1 });
        });

        it('should stop at an absurd depth rather than overflow', function () {
            let deep = { password: 'x' };
            for (let i = 0; i < 100; i++) deep = { deep };
            assert.doesNotThrow(() => redact(deep, { auto: true }));
        });
    });
});

describe('redactString()', function () {
    it('should only handle strings', function () {
        assert.strictEqual(redactString(1, { auto: true }), 1);
        assert.strictEqual(redactString(undefined, { auto: true }), undefined);
    });

    it('should mask the secret shapes of auto and values, with the placeholder given', function () {
        const line = `1.2.3.4 - - "GET /f?signature=abcdef12&n=1 HTTP/1.1" 200 "Bearer ${jwt}"`;
        assert.strictEqual(
            redactString(line, { auto: true, placeholder: '***' }),
            '1.2.3.4 - - "GET /f?signature=***&n=1 HTTP/1.1" 200 "Bearer ***"');
        assert.strictEqual(redactString('a 123456', { values: [/\d{6}/] }), 'a [Filtered]');
        assert.strictEqual(redactString(line), line);
    });
});

describe('secrets', function () {
    it('should tell which keys are secret', function () {
        assert.strictEqual(secrets.isSecretKey('x-api-key'), true);
        assert.strictEqual(secrets.isSecretKey('passport'), false);
    });

    it('should tell which entries are secret, by name and value', function () {
        assert.strictEqual(secrets.isSecretEntry('token', 'abc'), true);
        assert.strictEqual(secrets.isSecretEntry('token', false), false);
        assert.strictEqual(secrets.isSecretEntry('cookie', {}), false);
        assert.strictEqual(secrets.isSecretEntry('cookie', 'a=1'), true);
    });

    it('should hand out the value patterns as copies', function () {
        const patterns = secrets.valuePatterns();
        assert(patterns.length > 0 && patterns.every(p => p instanceof RegExp));
        assert.notStrictEqual(patterns[0], secrets.valuePatterns()[0]);
    });
});
