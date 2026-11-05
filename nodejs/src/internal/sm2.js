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

// SM2 public-key decryption (GM/T 0003.4) with ASN.1 C1C3C2 ciphertext,
// matching gmsm sm2.ASN1DecrypterOpts used by the Go SDK.
//
// Node's privateDecrypt does not support SM2, and OpenSSL's SM2 ECDH is broken
// in some Node.js releases (e.g. 24.22 / OpenSSL 3.5.9), so the curve math is
// delegated to sm-crypto-v2 (built on @noble/curves).

const { sm2 } = require('sm-crypto-v2');

const { ErrorCode, KmsError } = require('../errors');
const { decodeBase64, decodePrivateKey, parseDer, derChildren, toFixedBytes } = require('./encoding');

const FIELD_SIZE = 32;
const C1C3C2 = 1;
const TAG_INTEGER = 0x02;
const TAG_OCTET_STRING = 0x04;
const TAG_OID = 0x06;
const TAG_SEQUENCE = 0x30;
const TAG_CONTEXT_0 = 0xa0;
const OID_EC_PUBLIC_KEY = '2a8648ce3d0201'; // 1.2.840.10045.2.1
const OID_SM2 = '2a811ccf5501822d'; // 1.2.156.10197.1.301
const N = 0xfffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123n;

function expectTag(tlv, tag) {
  if (!tlv || tlv.tag !== tag) {
    throw new Error('unexpected DER structure');
  }
  return tlv.value;
}

/** Extracts the private scalar (hex) from an SM2 PKCS#8 PrivateKeyInfo. */
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
  const hex = d.toString('hex');
  const scalar = BigInt(`0x${hex}`);
  if (scalar < 1n || scalar > N - 2n) {
    throw new Error('SM2 private key is out of range');
  }
  return hex;
}

function sm2Decrypt(encodedText, privateKeyBase64) {
  const ciphertext = decodeBase64(encodedText);
  if (!ciphertext) {
    throw new KmsError(ErrorCode.DECRYPT_FAILED, 'SM2 encrypted key is not valid base64');
  }

  const der = decodePrivateKey(privateKeyBase64);
  if (!der) {
    throw new KmsError(ErrorCode.INVALID_PRIVATE_KEY, 'private key is not a base64-encoded PEM');
  }

  let privateKeyHex;
  try {
    privateKeyHex = parsePrivateKey(der);
  } catch (cause) {
    throw new KmsError(ErrorCode.INVALID_PRIVATE_KEY, 'private key is not an SM2 PKCS#8 key', { cause });
  }

  let output;
  try {
    output = sm2.doDecrypt(ciphertext.toString('hex'), privateKeyHex, C1C3C2, { asn1: true, output: 'array' });
  } catch (cause) {
    throw new KmsError(ErrorCode.DECRYPT_FAILED, 'SM2 ciphertext is malformed', { cause });
  }

  // sm-crypto-v2 signals a C3 mismatch (wrong key, tampered data) with an empty result.
  if (!output || output.length === 0) {
    throw new KmsError(ErrorCode.DECRYPT_FAILED, 'SM2 decryption failed');
  }
  const plaintext = Buffer.from(output);
  if (typeof output.fill === 'function') {
    output.fill(0);
  }
  return plaintext;
}

module.exports = { sm2Decrypt };
