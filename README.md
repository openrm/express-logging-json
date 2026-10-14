# express-logging-json
A JSON logging helper for Express

## Installation
```bash
npm install express-logging-json
```

## Usage
A simple logging middleware example, with [on-finished](https://github.com/jshttp/on-finished) module:
```js
const onFinished = require('on-finished');
const format = require('express-logging-json');

const options = {
    mask: {
        fields: ['headers.authorization']
    }
};

const app = express();

app.use((req, res, next) => {
    onFinished(res, err => {
        const log = format(req, res, options);
        log.err = err;
        console.info(log);
    });
    next();
});
```

## Leaving parts out
A log refers to a lot of what a request carries, and an access log is written for every request. To log less, leave out what is not needed with `omit`: paths, or regular expressions tested against them.

```js
const options = {
    omit: [
        'trailers', // a top-level key
        'headers.accept-language', // a path
        /^headers\.sec-/ // everything a regular expression matches
    ]
};
```

Paths are dotted, as in `mask.fields`. The items of an array share the path of the array, so `items.note` leaves out `note` in every item. Like masking, it works on a copy and never changes the request. It can be combined with `mask`.

## Masking secrets
A request log refers to everything a request carries: headers, cookies, session, query, body. Secrets in there are easy to miss, so masking can be done by path, by name or by what a value looks like. Masking works on a copy: the request, session and response are never changed.

```js
const options = {
    mask: {
        fields: ['body.card.number'], // an exact path
        keys: ['pin', /^x-internal-/i], // names, at any depth
        values: [/\b\d{16}\b/], // matches within any string
        auto: true, // the names and shapes that most secrets have, see below
        except: [/^x-token-/i] // names that only sound secret, see below
    }
};
```

`auto` masks:
- keys named like secrets, as whole words: `password`, `secret`, `token`, `credentials`, `authorization`, `signature`, `jwt`, `csrf`, `api key`, `session id` and the like, in any style (`x-auth-token`, `csrfSecret`, `API_KEY`), and the `Cookie` and `Set-Cookie` headers. Words that merely contain these letters, such as `passport` or `author`, are left alone
- the values of those keys, unless there is nothing to hide: flags, nulls, and `cookie` objects that are only settings
- recognisable secrets in any string, whatever the key is called: JSON web tokens, the credentials of `Bearer` and `Basic` values, well known vendor keys, PEM private keys, and secret-looking query parameters such as `token` or `signature`, as in a `url`

Only the secret part is replaced, so `Bearer [Filtered]` and `?signature=[Filtered]&page=2` stay readable. Long hex or base64 strings are not treated as secrets: they are at least as often ids.

A name can sound secret and hold something harmless, such as an id in a `token-user` header. List those in `except` and `auto` leaves them alone by name. What is inside is still checked, so a real token in an excepted header is masked all the same. `keys` and `fields` take precedence over `except`.

Masking is a safety net, not a guarantee. A secret under an innocent name, in an unrecognisable shape, is not found.

The same helpers can be used on other parts of a log, such as a text line:

```js
const { redact, redactString, secrets } = require('express-logging-json');

redactString('GET /file?signature=abc123 HTTP/1.1', { auto: true });
// 'GET /file?signature=[Filtered] HTTP/1.1'

redact(anyObject, { auto: true, except: ['x-token-user'] }); // a masked copy
secrets.isSecretKey('x-api-key'); // true
```
