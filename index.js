module.exports = format;
module.exports.mask = mask;
module.exports.format = format;
module.exports.redact = redact;
module.exports.redactString = redactString;
module.exports.secrets = { isSecretKey, isSecretEntry, valuePatterns: () => DEFAULT_VALUE_PATTERNS.map(clonePattern) };

const PLACEHOLDER = '[Filtered]';

function mask (obj, fields = [], { placeholder = '[Filtered]' } = {}) {
    for (const field of fields) {
        const keys = field.split('.'),
            last = keys.pop();
        const o = keys.reduce((obj, key) => obj[key] ?? {}, obj);
        if (last in o) o[last] = placeholder;
    }
}

// Words that make a key name secret: `password`, `x-auth-token`, `csrfSecret`, `sessionToken`, `API_KEY`
// but not `passport`, `author` or `tokenizer`. Names are split into words on non-alphanumerics and
// camelCase before they are compared, so only whole words count.
const SECRET_WORDS = new Set([
    'password', 'passwords', 'passwd', 'pwd', 'passphrase',
    'secret', 'secrets', 'token', 'tokens', 'credential', 'credentials',
    'authorization', 'signature', 'jwt', 'csrf', 'xsrf', 'apikey'
]);
// Pairs of words that are secret only together
const SECRET_PHRASES = [
    ['api', 'key'], ['private', 'key'], ['access', 'key'], ['session', 'id'], ['session', 'key']
];

// The Cookie and Set-Cookie headers carry whole sessions. A `cookie` that is an object is rather
// the settings of a cookie, as in `req.session.cookie`, and has nothing to hide.
const COOKIE_HEADER = /^(?:set-)?cookie$/i;

const keyCache = new Map();

function isSecretKey (key) {
    key = String(key);
    let secret = keyCache.get(key);
    if (secret === undefined) {
        const words = key
            .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
            .replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2')
            .toLowerCase()
            .split(/[^a-z0-9]+/)
            .filter(Boolean);
        secret = words.some(word => SECRET_WORDS.has(word)) ||
            SECRET_PHRASES.some(([a, b]) => words.some((w, i) => w === a && words[i + 1] === b));
        if (keyCache.size > 1000) keyCache.clear();
        keyCache.set(key, secret);
    }
    return secret;
}

// Shapes of secrets that are recognisable whatever they are called. Only the secret part is replaced,
// so `Bearer <jwt>` and `?signature=<value>` stay readable. Deliberately not entropy based: long hex or
// base64 strings are as likely to be ids as secrets.
const DEFAULT_VALUE_PATTERNS = [
    /eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*/g, // JSON web tokens
    /(?<=\b(?:Bearer|Basic)\s+)[A-Za-z0-9._~+/=-]{12,}/gi, // credentials in an Authorization value
    /\b(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|sk_(?:live|test)_[A-Za-z0-9]{16,}|xox[abprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{30,})/g, // well known vendor keys
    /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)/g, // PEM private keys
    /(?<=[?&;](?:access_token|refresh_token|id_token|token|api_key|apikey|client_secret|secret|password|passwd|signature|sig|x-goog-signature|x-amz-signature)=)[^&#\s"']+/gi // secrets in query strings
];

function clonePattern (pattern) {
    return new RegExp(pattern.source, pattern.flags);
}

// replace() on a pattern without the global flag would only replace the first match
function globally (pattern) {
    return pattern.global ? pattern : new RegExp(pattern.source, pattern.flags + 'g');
}

function isContainer (value) {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
}

// Nothing to hide in a flag: `access-control-allow-credentials: true`, `token: false`
function isInformative (value) {
    return value !== null && value !== undefined && typeof value !== 'boolean' &&
        value !== 'true' && value !== 'false';
}

function isSecretEntry (key, value) {
    if (!isInformative(value)) return false;
    return isSecretKey(key) || (COOKIE_HEADER.test(key) && !isContainer(value));
}

// A test of a key name, from a string (compared ignoring case) or a regular expression
function nameTest (key) {
    return key instanceof RegExp ?
        (name) => { key.lastIndex = 0; return key.test(name); } :
        (name) => name.toLowerCase() === String(key).toLowerCase();
}

function compile ({ keys = [], values = [], except = [], auto = false } = {}) {
    const keyTests = keys.map(nameTest);
    if (auto) {
        const excepted = except.map(nameTest);
        // `except` only lifts the rule by name: what is in an excepted key is still checked for secrets
        keyTests.push((name, value) => !excepted.some(test => test(name)) && isSecretEntry(name, value));
    }
    const patterns = [...(auto ? DEFAULT_VALUE_PATTERNS : []), ...values].map(globally);
    return { keyTests, patterns };
}

function replacePatterns (string, patterns, placeholder) {
    for (const pattern of patterns) {
        pattern.lastIndex = 0;
        string = string.replace(pattern, placeholder);
    }
    return string;
}

/**
 * Masks the secret-like strings in plain text, such as a request line of an access log.
 * Only `values` and `auto` apply, there are no keys in a string.
 */
function redactString (string, { placeholder = PLACEHOLDER, ...options } = {}) {
    if (typeof string !== 'string') return string;
    return replacePatterns(string, compile(options).patterns, placeholder);
}

const MAX_DEPTH = 30;

/**
 * Returns a copy of `value` with the secrets masked, wherever they are in it. The original is never
 * changed, which matters as a request log refers to the live request, headers and session.
 *
 * - `keys`: names whose values are replaced: strings (case insensitive) or regular expressions
 * - `values`: regular expressions whose matches are replaced in every string
 * - `auto`: also use the names and shapes in `secrets`, which is what most secrets look like
 * - `except`: names (as in `keys`) that `auto` does not mask by name, for the ones that only look like
 *   secrets. Their values are still checked for secret shapes, and `keys` wins over `except`
 * - `placeholder`: what to replace with, '[Filtered]' by default
 */
function redact (value, options = {}) {
    const { placeholder = PLACEHOLDER } = options;
    const { keyTests, patterns } = compile(options);
    const seen = new WeakMap();

    function walk (v, depth) {
        if (typeof v === 'string') return patterns.length ? replacePatterns(v, patterns, placeholder) : v;
        if (v === null || typeof v !== 'object') return v;
        if (seen.has(v)) return seen.get(v);
        if (depth > MAX_DEPTH) return '[Truncated]';
        const type = Object.prototype.toString.call(v);

        if (Array.isArray(v)) {
            const copy = [];
            seen.set(v, copy);
            for (const item of v) copy.push(walk(item, depth + 1));
            return copy;
        }
        // Buffers, dates, errors and the like are not containers of named values
        if (type !== '[object Object]') return v;
        // Honour toJSON, as what is logged will be serialised anyway (dates, ids, documents)
        if (typeof v.toJSON === 'function') {
            const json = v.toJSON();
            if (json !== v) return walk(json, depth + 1);
        }

        const copy = {};
        seen.set(v, copy);
        for (const key of Object.keys(v)) {
            copy[key] = keyTests.some(test => test(key, v[key])) ? placeholder : walk(v[key], depth + 1);
        }
        return copy;
    }

    return walk(value, 0);
}

function format (req, res, options = {}) {
    const { maxBodyLen = 10_000 } = options;

    const log = {
        ip: req.ip,
        ips: req.ips,
        hostname: req.hostname,
        protocol: req.protocol,
        protocolVersion: req.httpVersion,
        method: req.method,
        url: req.originalUrl ?? req.url,
        path: req.path,
        fresh: req.fresh,
        subdomains: req.subdomains,
        xhr: req.xhr,
        referer: req.header('Referrer') ?? req.header('Referer'),
        userAgent: req.header('User-Agent'),
        remoteAdress: req.connection.remoteAddress,
        remotePort: req.connection.remotePort,
        headers: req.headers,
        trailers: req.trailers,
        query: req.query,
        params: req.params,
        session: req.session,
        user: req.user,
        files: req.files,
        cookies: req.cookies,
        signedCookies: req.signedCookies,
        status: res.statusCode,
        locals: res.locals,
        responseHeaders: res.getHeaders()
    };

    try {
        const bodyLen = JSON.stringify(req.body)?.length;
        if (!maxBodyLen || bodyLen <= maxBodyLen) log.body = req.body;
    } catch {
        // not serializable
    }

    if (options.mask) {
        const { fields, ...opts } = options.mask;
        // `log` refers to the live request, response and session: work on a copy so that masking
        // never changes them
        const masked = redact(log, opts);
        mask(masked, fields, opts);
        return masked;
    }

    return log;
}
