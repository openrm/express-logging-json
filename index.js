module.exports = format;
module.exports.mask = mask;
module.exports.format = format;

function mask (obj, fields = [], { placeholder = '[Filtered]' } = {}) {
    for (const field of fields) {
        const keys = field.split('.'),
            last = keys.pop();
        const o = keys.reduce((obj, key) => obj[key] ?? {}, obj);
        if (last in o) o[last] = placeholder;
    }
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
        mask(log, fields, opts);
    }

    return log;
}
