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

const { ErrorCode, KmsError } = require('./errors');
const { decodeBase64 } = require('./internal/encoding');
const { rsaDecrypt } = require('./internal/rsa');
const { sm2Decrypt } = require('./internal/sm2');
const { decryptSymmetric, BLOCK_SIZE } = require('./internal/symmetric');

const ASYMMETRIC = { RSA: rsaDecrypt, SM2: sm2Decrypt };
const SYMMETRIC_TYPES = ['AES', 'SM4'];
const SYMMETRIC_MODES = ['CBC', 'CTR'];
const FIELDS = ['asymmetric_type', 'symmetric_type', 'symmetric_mode', 'encrypted_key', 'ciphertext'];

// ignoreBOM keeps a leading BOM so JSON.parse rejects it, and so plaintext is returned unchanged.
const utf8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

function requireString(name, value) {
  if (typeof value !== 'string' || value === '') {
    throw new KmsError(ErrorCode.INVALID_ARGUMENT, `${name} must be a non-empty string`);
  }
}

function parseEnvelope(envelope) {
  const raw = decodeBase64(envelope);
  if (!raw) {
    throw new KmsError(ErrorCode.INVALID_ENVELOPE, 'credential envelope is not valid base64');
  }

  let payload;
  try {
    payload = JSON.parse(utf8.decode(raw));
  } catch (cause) {
    throw new KmsError(ErrorCode.INVALID_ENVELOPE, 'credential envelope is not valid JSON', { cause });
  }
  if (payload === null || typeof payload !== 'object' || Array.isArray(payload)) {
    throw new KmsError(ErrorCode.INVALID_ENVELOPE, 'credential envelope must be a JSON object');
  }

  const fields = {};
  for (const name of FIELDS) {
    const value = Object.hasOwn(payload, name) ? payload[name] : undefined;
    if (typeof value !== 'string' || value === '') {
      throw new KmsError(ErrorCode.INVALID_ENVELOPE, `credential envelope field "${name}" must be a non-empty string`);
    }
    fields[name] = value;
  }

  const checks = [
    ['asymmetric_type', Object.hasOwn(ASYMMETRIC, fields.asymmetric_type)],
    ['symmetric_type', SYMMETRIC_TYPES.includes(fields.symmetric_type)],
    ['symmetric_mode', SYMMETRIC_MODES.includes(fields.symmetric_mode)],
  ];
  for (const [name, ok] of checks) {
    if (!ok) {
      throw new KmsError(ErrorCode.UNSUPPORTED_ALGORITHM, `unsupported ${name} "${fields[name]}"`);
    }
  }

  return fields;
}

/**
 * Decrypts a Base64 JSON hybrid envelope with its matching Base64 PEM private key.
 *
 * @param {string} envelope Base64-encoded envelope issued by BK-KMS.
 * @param {string} privateKey Base64-encoded PEM private key (RSA PKCS#8/PKCS#1 or SM2 PKCS#8).
 * @returns {string} The original UTF-8 plaintext.
 * @throws {KmsError}
 */
function decrypt(envelope, privateKey) {
  requireString('envelope', envelope);
  requireString('private key', privateKey);

  const fields = parseEnvelope(envelope);

  const dataKey = ASYMMETRIC[fields.asymmetric_type](fields.encrypted_key, privateKey);
  let plaintext;
  try {
    if (dataKey.length !== BLOCK_SIZE) {
      throw new KmsError(ErrorCode.DECRYPT_FAILED, `data key must be exactly ${BLOCK_SIZE} bytes`);
    }
    plaintext = decryptSymmetric(fields.ciphertext, fields.symmetric_type, fields.symmetric_mode, dataKey);
  } finally {
    dataKey.fill(0);
  }

  try {
    return utf8.decode(plaintext);
  } catch (cause) {
    throw new KmsError(ErrorCode.INVALID_PLAINTEXT, 'decrypted plaintext is not valid UTF-8', { cause });
  }
}

module.exports = { decrypt };
