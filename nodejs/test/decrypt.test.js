'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { describe, it } = require('node:test');

const { decrypt, ErrorCode, KmsError } = require('../src');
const { rsaDecrypt } = require('../src/internal/rsa');
const { sm2Decrypt } = require('../src/internal/sm2');
const { decryptSymmetric } = require('../src/internal/symmetric');
const interop = require('./fixtures/interop_vectors.json');
const sm2Binary = require('./fixtures/sm2_binary_key.json');
const pythonKeys = require('./fixtures/python_key_interop_vectors.json');

const b64 = (value) => Buffer.from(value).toString('base64');
const encodeEnvelope = (obj) => b64(JSON.stringify(obj));
const parseEnvelope = (envelope) => JSON.parse(Buffer.from(envelope, 'base64').toString('utf8'));

function expectCode(fn, code) {
  assert.throws(fn, (err) => err instanceof KmsError && err.code === code);
}

function rsaKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  return { publicKey, privateKey: b64(privateKey.export({ format: 'pem', type: 'pkcs8' })) };
}

function encryptSymmetric(plaintext, type, mode, key) {
  const name = `${type.toLowerCase() === 'aes' ? 'aes-128' : 'sm4'}-${mode.toLowerCase()}`;
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(name, key, iv);
  cipher.setAutoPadding(mode === 'CBC');
  return Buffer.concat([iv, cipher.update(plaintext), cipher.final()]).toString('base64');
}

function makeRsaEnvelope(plaintext, publicKey, { type = 'AES', mode = 'CBC', key = crypto.randomBytes(16) } = {}) {
  const encryptedKey = crypto.publicEncrypt(
    { key: publicKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
    key,
  );
  return encodeEnvelope({
    asymmetric_type: 'RSA',
    symmetric_type: type,
    symmetric_mode: mode,
    encrypted_key: encryptedKey.toString('base64'),
    ciphertext: encryptSymmetric(Buffer.from(plaintext), type, mode, key),
  });
}

describe('Go-generated interop vectors', () => {
  it('contains all eight algorithm combinations', () => {
    assert.equal(Object.keys(interop.vectors).length, 8);
  });

  for (const [name, vector] of Object.entries(interop.vectors)) {
    it(`decrypts ${name}`, () => {
      assert.equal(decrypt(vector.envelope, vector.private_key), interop.plaintext);
    });
  }

  it('accepts the RSA key re-encoded as PKCS#8', () => {
    const vector = interop.vectors.rsa_aes_cbc;
    const pem = Buffer.from(vector.private_key, 'base64').toString();
    assert.match(pem, /BEGIN RSA PRIVATE KEY/);
    const pkcs8 = crypto.createPrivateKey(pem).export({ format: 'pem', type: 'pkcs8' });
    assert.equal(decrypt(vector.envelope, b64(pkcs8)), interop.plaintext);
  });

  it('preserves a non-UTF-8 binary data key through SM2', () => {
    const key = sm2Decrypt(sm2Binary.ciphertext, sm2Binary.private_key);
    assert.equal(key.toString('base64'), sm2Binary.plaintext_b64);
  });

  it('decrypts Go-encrypted binary data keys with stored RSA and SM2 keys', () => {
    const { rsa, sm2 } = pythonKeys.vectors;
    assert.equal(rsaDecrypt(rsa.ciphertext, rsa.private_key).toString('base64'), pythonKeys.plaintext_b64);
    assert.equal(sm2Decrypt(sm2.ciphertext, sm2.private_key).toString('base64'), pythonKeys.plaintext_b64);
  });
});

describe('round trips', () => {
  const { publicKey, privateKey } = rsaKeyPair();

  for (const type of ['AES', 'SM4']) {
    for (const mode of ['CBC', 'CTR']) {
      for (const plaintext of ['{"a":1}', 'plain text', '  \n\t ', '蓝鲸 🔐', 'x'.repeat(16), 'y'.repeat(1000)]) {
        it(`RSA/${type}/${mode} ${JSON.stringify(plaintext.slice(0, 12))}`, () => {
          assert.equal(decrypt(makeRsaEnvelope(plaintext, publicKey, { type, mode }), privateKey), plaintext);
        });
      }
    }
  }

  it('CBC returns an empty string for a padding-only payload', () => {
    assert.equal(decrypt(makeRsaEnvelope('', publicKey, { mode: 'CBC' }), privateKey), '');
  });

  it('CTR requires at least one payload byte, like Go', () => {
    expectCode(() => decrypt(makeRsaEnvelope('', publicKey, { mode: 'CTR' }), privateKey), ErrorCode.DECRYPT_FAILED);
  });

  it('keeps a leading BOM in plaintext unchanged', () => {
    assert.equal(decrypt(makeRsaEnvelope('\ufeffhi', publicKey), privateKey), '\ufeffhi');
  });
});

describe('invalid input', () => {
  const vector = interop.vectors.sm2_sm4_ctr;
  const fields = parseEnvelope(vector.envelope);

  it('rejects empty or non-string arguments', () => {
    for (const [envelope, key] of [
      ['', 'k'],
      ['e', ''],
      [undefined, 'k'],
      ['e', null],
      [Buffer.from('e'), 'k'],
    ]) {
      expectCode(() => decrypt(envelope, key), ErrorCode.INVALID_ARGUMENT);
    }
  });

  it('rejects envelopes that are not strict base64 JSON objects', () => {
    for (const envelope of [
      'not base64!',
      'YWJj',
      vector.envelope.replace(/=+$/, ''),
      b64('[1]'),
      b64('null'),
      b64('"str"'),
      b64(`\ufeff${JSON.stringify(fields)}`),
      Buffer.concat([Buffer.from('{"a":"'), Buffer.from([0xff]), Buffer.from('"}')]).toString('base64'),
    ]) {
      expectCode(() => decrypt(envelope, vector.private_key), ErrorCode.INVALID_ENVELOPE);
    }
  });

  it('rejects missing, empty or non-string fields', () => {
    for (const name of Object.keys(fields)) {
      for (const value of [undefined, '', 1, null]) {
        const envelope = encodeEnvelope({ ...fields, [name]: value });
        expectCode(() => decrypt(envelope, vector.private_key), ErrorCode.INVALID_ENVELOPE);
      }
    }
  });

  it('does not read fields from the prototype chain', () => {
    const envelope = encodeEnvelope({ ...fields, asymmetric_type: 'constructor' });
    expectCode(() => decrypt(envelope, vector.private_key), ErrorCode.UNSUPPORTED_ALGORITHM);
  });

  it('rejects unsupported algorithms case-sensitively', () => {
    for (const [name, value] of [
      ['asymmetric_type', 'sm2'],
      ['asymmetric_type', 'ECC'],
      ['symmetric_type', 'DES'],
      ['symmetric_mode', 'GCM'],
    ]) {
      const envelope = encodeEnvelope({ ...fields, [name]: value });
      expectCode(() => decrypt(envelope, vector.private_key), ErrorCode.UNSUPPORTED_ALGORITHM);
    }
  });

  it('rejects malformed private keys', () => {
    for (const key of ['not base64!', b64('no pem here'), b64('-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n')]) {
      expectCode(() => decrypt(vector.envelope, key), ErrorCode.INVALID_PRIVATE_KEY);
    }
  });

  it('rejects a key of the wrong algorithm', () => {
    expectCode(() => decrypt(vector.envelope, interop.vectors.rsa_aes_cbc.private_key), ErrorCode.INVALID_PRIVATE_KEY);
    expectCode(() => decrypt(interop.vectors.rsa_aes_cbc.envelope, vector.private_key), ErrorCode.INVALID_PRIVATE_KEY);
  });

  it('rejects a mismatched key without leaking secrets', () => {
    const { publicKey } = rsaKeyPair();
    const other = rsaKeyPair();
    const secret = 'top-secret-plaintext';
    const envelope = makeRsaEnvelope(secret, publicKey);
    const sm2Envelope = interop.vectors.sm2_aes_cbc.envelope;

    for (const [env, key] of [
      [envelope, other.privateKey],
      [sm2Envelope, sm2Binary.private_key],
    ]) {
      assert.throws(
        () => decrypt(env, key),
        (err) => {
          assert.equal(err.code, ErrorCode.DECRYPT_FAILED);
          for (const s of [secret, env, key, interop.plaintext]) {
            assert.ok(!err.message.includes(s));
          }
          return true;
        },
      );
    }
  });

  it('rejects tampered SM2 ciphertext', () => {
    const raw = Buffer.from(fields.encrypted_key, 'base64');
    raw[raw.length - 1] ^= 1;
    const envelope = encodeEnvelope({ ...fields, encrypted_key: raw.toString('base64') });
    expectCode(() => decrypt(envelope, vector.private_key), ErrorCode.DECRYPT_FAILED);

    const truncated = encodeEnvelope({ ...fields, encrypted_key: raw.subarray(0, 40).toString('base64') });
    expectCode(() => decrypt(truncated, vector.private_key), ErrorCode.DECRYPT_FAILED);
  });

  it('rejects an SM2 C1 point that is not on the curve', () => {
    const tlv = (tag, body) => Buffer.concat([Buffer.from([tag, body.length]), body]);
    const offCurve = tlv(
      0x30,
      Buffer.concat([
        tlv(0x02, Buffer.from([1])),
        tlv(0x02, Buffer.from([1])),
        tlv(0x04, Buffer.alloc(32)),
        tlv(0x04, Buffer.from([0])),
      ]),
    );
    expectCode(() => sm2Decrypt(offCurve.toString('base64'), vector.private_key), ErrorCode.DECRYPT_FAILED);
  });

  it('rejects data keys that are not 16 bytes', () => {
    const { publicKey, privateKey } = rsaKeyPair();
    const key = crypto.randomBytes(24);
    const encryptedKey = crypto.publicEncrypt(
      { key: publicKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
      key,
    );
    const envelope = encodeEnvelope({
      asymmetric_type: 'RSA',
      symmetric_type: 'AES',
      symmetric_mode: 'CTR',
      encrypted_key: encryptedKey.toString('base64'),
      ciphertext: b64('x'.repeat(32)),
    });
    expectCode(() => decrypt(envelope, privateKey), ErrorCode.DECRYPT_FAILED);
  });

  it('rejects non-UTF-8 plaintext', () => {
    const { publicKey, privateKey } = rsaKeyPair();
    expectCode(() => decrypt(makeRsaEnvelope(Buffer.from([0xc3, 0x28]), publicKey), privateKey), ErrorCode.INVALID_PLAINTEXT);
  });
});

describe('symmetric layer', () => {
  const key = crypto.randomBytes(16);

  it('rejects bad CBC lengths and padding', () => {
    for (const type of ['AES', 'SM4']) {
      expectCode(() => decryptSymmetric(b64(Buffer.alloc(16)), type, 'CBC', key), ErrorCode.DECRYPT_FAILED);
      expectCode(() => decryptSymmetric(b64(Buffer.alloc(33)), type, 'CBC', key), ErrorCode.DECRYPT_FAILED);
      expectCode(() => decryptSymmetric('***', type, 'CBC', key), ErrorCode.DECRYPT_FAILED);

      // Valid block length, but padding check fails under a different key.
      const ct = encryptSymmetric(Buffer.from('hello world'), type, 'CBC', key);
      expectCode(() => decryptSymmetric(ct, type, 'CBC', crypto.randomBytes(16)), ErrorCode.DECRYPT_FAILED);
    }
  });

  it('rejects CTR payloads without data', () => {
    expectCode(() => decryptSymmetric(b64(Buffer.alloc(16)), 'SM4', 'CTR', key), ErrorCode.DECRYPT_FAILED);
  });

  it('uses a full 128-bit big-endian counter in CTR', () => {
    const iv = Buffer.alloc(16, 0xff);
    const plaintext = crypto.randomBytes(48);
    for (const name of ['aes-128-ecb', 'sm4-ecb']) {
      const ecb = crypto.createCipheriv(name, key, null).setAutoPadding(false);
      const counters = [iv, Buffer.alloc(16), Buffer.concat([Buffer.alloc(15), Buffer.from([1])])];
      const stream = Buffer.concat([ecb.update(Buffer.concat(counters)), ecb.final()]);
      const ct = Buffer.alloc(48);
      for (let i = 0; i < 48; i++) ct[i] = plaintext[i] ^ stream[i];
      const type = name.startsWith('aes') ? 'AES' : 'SM4';
      assert.deepEqual(decryptSymmetric(b64(Buffer.concat([iv, ct])), type, 'CTR', key), plaintext);
    }
  });
});
