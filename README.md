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
