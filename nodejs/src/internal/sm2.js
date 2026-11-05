/*
 * TencentBlueKing is pleased to support the open source community by making
 * 蓝鲸智云 - 凭证管理服务(BlueKing - Key Management Service) available.
 * Copyright (C) 2022 THL A29 Limited, a Tencent company. All rights reserved.
 * Licensed under the MIT License (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 * http://opensource.org/licenses/MIT
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.We undertake not
 * to change the open source license (MIT license) applicable to the current version
 * of the project delivered to anyone in the future.
 */

'use strict';

// SM2 public-key decryption (GM/T 0003.4) with ASN.1 ciphertext
// SEQUENCE { INTEGER x1, INTEGER y1, OCTET STRING C3, OCTET STRING C2 },
// matching gmsm sm2.ASN1DecrypterOpts used by the Go SDK.
//
// Node's privateDecrypt does not support SM2, so the shared point [d]C1 is
// computed with ECDH on the SM2 curve. ECDH only yields x2; both possible y2
// values are tried and the one passing the C3 integrity check is accepted.

const crypto = require('node:crypto');

const { ErrorCode, KmsError } = require('../errors');
const { decodeBase64, decodePrivateKey, parseDer, derChildren, toFixedBytes } = require('./encoding');

const FIELD_SIZE = 32;
const SM3_SIZE = 32;
const TAG_INTEGER = 0x02;
const TAG_OCTET_STRING = 0x04;
const TAG_OID = 0x06;
const TAG_SEQUENCE = 0x30;
const TAG_CONTEXT_0 = 0xa0;
const OID_EC_PUBLIC_KEY = '2a8648ce3d0201'; // 1.2.840.10045.2.1
const OID_SM2 = '2a811ccf5501822d'; // 1.2.156.10197.1.301

function ensureAvailable() {
  if (!crypto.getCurves().includes('SM2') || !crypto.getHashes().includes('sm3')) {
    throw new KmsError(
      ErrorCode.ALGORITHM_UNAVAILABLE,
      'SM2/SM3 is not supported by the OpenSSL build used by this Node.js runtime',
    );
  }
}

function expectTag(tlv, tag) {
  if (!tlv || tlv.tag !== tag) {
    throw new Error('unexpected DER structure');
  }
  return tlv.value;
}

/** Extracts the 32-byte private scalar from an SM2 PKCS#8 PrivateKeyInfo. */
function parsePrivateKey(der) {
  const info = derChildren(parseDer(der, TAG_SEQUENCE).value);
  const version = expectTag(info[0], TAG_INTEGER);
  if (version.length !== 1 || version[0] !== 0) {
    throw new Error('unsupported PKCS#8 version');
  }

  const algorithm = derChildren(expectTag(info[1], TAG_SEQUENCE));
  const algorithmOid = expectTag(algorithm[0], TAG_OID).toString('hex');
  if (algorithmOid === OID_EC_PUBLIC_KEY) {
    if (expectTag(algorithm[1], TAG_OID).toString('hex') !== OID_SM2) {
      throw new Error('EC private key is not on the SM2 curve');
    }
  } else if (algorithmOid !== OID_SM2) {
    throw new Error('not an SM2 private key');
  }

  const ecKey = derChildren(parseDer(expectTag(info[2], TAG_OCTET_STRING), TAG_SEQUENCE).value);
  const ecVersion = expectTag(ecKey[0], TAG_INTEGER);
  if (ecVersion.length !== 1 || ecVersion[0] !== 1) {
    throw new Error('unsupported EC private key version');
  }
  const params = ecKey.slice(2).find((tlv) => tlv.tag === TAG_CONTEXT_0);
  if (params && parseDer(params.value, TAG_OID).value.toString('hex') !== OID_SM2) {
    throw new Error('EC private key is not on the SM2 curve');
  }

  const d = toFixedBytes(expectTag(ecKey[1], TAG_OCTET_STRING), FIELD_SIZE);
  if (!d) {
    throw new Error('invalid SM2 private key length');
  }
  return d;
}

function parseCoordinate(tlv) {
  const value = expectTag(tlv, TAG_INTEGER);
  if (value.length === 0 || value[0] & 0x80) {
    throw new Error('invalid SM2 point coordinate');
  }
  const fixed = toFixedBytes(value, FIELD_SIZE);
  if (!fixed) {
    throw new Error('invalid SM2 point coordinate');
  }
  return fixed;
}

function parseCiphertext(buf) {
  const parts = derChildren(parseDer(buf, TAG_SEQUENCE).value);
  if (parts.length !== 4) {
    throw new Error('invalid SM2 ciphertext structure');
  }
  const x1 = parseCoordinate(parts[0]);
  const y1 = parseCoordinate(parts[1]);
  const c3 = expectTag(parts[2], TAG_OCTET_STRING);
  const c2 = expectTag(parts[3], TAG_OCTET_STRING);
  if (c3.length !== SM3_SIZE || c2.length === 0) {
    throw new Error('invalid SM2 ciphertext structure');
  }
  return { c1: Buffer.concat([Buffer.from([0x04]), x1, y1]), c3, c2 };
}

function kdf(x2, y2, length) {
  const blocks = [];
  const counter = Buffer.alloc(4);
  for (let i = 1, produced = 0; produced < length; i++, produced += SM3_SIZE) {
    counter.writeUInt32BE(i);
    blocks.push(crypto.createHash('sm3').update(x2).update(y2).update(counter).digest());
  }
  return Buffer.concat(blocks).subarray(0, length);
}

function tryRecover(x2, prefix, c2, c3) {
  const point = crypto.ECDH.convertKey(
    Buffer.concat([Buffer.from([prefix]), x2]),
    'SM2',
    undefined,
    undefined,
    'uncompressed',
  );
  const y2 = point.subarray(1 + FIELD_SIZE);
  const t = kdf(x2, y2, c2.length);
  if (t.every((b) => b === 0)) {
    return null;
  }
  const message = Buffer.alloc(c2.length);
  for (let i = 0; i < c2.length; i++) {
    message[i] = c2[i] ^ t[i];
  }
  const u = crypto.createHash('sm3').update(x2).update(message).update(y2).digest();
  return crypto.timingSafeEqual(u, c3) ? message : null;
}

function sm2Decrypt(encodedText, privateKeyBase64) {
  ensureAvailable();

  const ciphertext = decodeBase64(encodedText);
  if (!ciphertext) {
    throw new KmsError(ErrorCode.DECRYPT_FAILED, 'SM2 encrypted key is not valid base64');
  }

  const der = decodePrivateKey(privateKeyBase64);
  if (!der) {
    throw new KmsError(ErrorCode.INVALID_PRIVATE_KEY, 'private key is not a base64-encoded PEM');
  }

  const ecdh = crypto.createECDH('SM2');
  try {
    ecdh.setPrivateKey(parsePrivateKey(der));
  } catch (cause) {
    throw new KmsError(ErrorCode.INVALID_PRIVATE_KEY, 'private key is not an SM2 PKCS#8 key', { cause });
  }

  let parsed;
  let x2;
  try {
    parsed = parseCiphertext(ciphertext);
    x2 = toFixedBytes(ecdh.computeSecret(parsed.c1), FIELD_SIZE);
  } catch (cause) {
    throw new KmsError(ErrorCode.DECRYPT_FAILED, 'SM2 ciphertext is malformed', { cause });
  }

  // Evaluate both candidates so the work done does not depend on the parity of y2.
  const even = tryRecover(x2, 0x02, parsed.c2, parsed.c3);
  const odd = tryRecover(x2, 0x03, parsed.c2, parsed.c3);
  const plaintext = even || odd;
  if (!plaintext) {
    throw new KmsError(ErrorCode.DECRYPT_FAILED, 'SM2 decryption failed');
  }
  return plaintext;
}

module.exports = { sm2Decrypt };
