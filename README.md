# express-logging-json
A JSON logging helper for Express

## Installation
```bash
npm i express-logging-json
```

## Usage
```js
const { format, mask } = require('express-logging-format');

const app = express();

app.get('/', (req, res) => {

    try {

        res.sendStatus(204);

        const log = format(req, res);

        mask(log, ['headers.authorization', 'fields.password']);

        console.log(log);

        done();

    } catch (err) {

        done(err);

    }
});
```