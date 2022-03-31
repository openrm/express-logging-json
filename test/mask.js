const assert = require('assert');
const { mask } = require('..');

describe('mask()', function () {
    it('should not throw for falsy values', function () {
        assert.doesNotThrow(() => mask(0));
        assert.doesNotThrow(() => mask(false));
        assert.doesNotThrow(() => mask(null));
        assert.doesNotThrow(() => mask(undefined));
    });

    it('should not do anything without options', function () {
        const o = { a: 1, b: 2, c: { d: 3 } };
        mask(o);
        assert.deepStrictEqual(o, { a: 1, b: 2, c: { d: 3 } });
    });

    it('should mask top-level fields', function () {
        const o1 = { a: 1, b: 2 };
        mask(o1, ['b', 'c']);
        assert.deepStrictEqual(o1, { a: 1, b: '[Filtered]' });

        const o2 = { a: 1, b: 2, c: 3 }, p = 'placeholder';
        mask(o2, ['b', 'c'], { placeholder: p });
        assert.deepStrictEqual(o2, { a: 1, b: p, c: p });
    });

    it('should mask nested fields', function () {
        const o = {
            a: 1,
            b: 2,
            c: { d: 1, e: 2 }
        };
        mask(o, ['b', 'c.d', 'f.g'], { placeholder: null });
        assert.deepStrictEqual(o, {
            a: 1,
            b: null,
            c: {
                d: null,
                e: 2
            }
        });
    });
});
