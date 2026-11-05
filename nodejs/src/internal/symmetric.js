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

const crypto = require('node:crypto');

const { ErrorCode, KmsError } = require('../errors');
const { decodeBase64 } = require('./encoding');

const BLOCK_SIZE = 16;

// Ciphertext layout: Base64(IV[16] || ciphertext). CTR uses a full 128-bit
// big-endian counter, as in Go's cipher.NewCTR and the Go SDK's SM4 CTR.
const CIPHERS = {
  AES: { CBC: 'aes-128-cbc', CTR: 'aes-128-ctr' },
  SM4: { CBC: 'sm4-cbc', CTR: 'sm4-ctr' },
};

function unpadPkcs7(data) {
  const pad = data[data.length - 1];
  let bad = pad === 0 || pad > BLOCK_SIZE ? 1 : 0;
  for (let i = 1; i <= BLOCK_SIZE; i++) {
    if (i <= pad && data[data.length - i] !== pad) {
      bad = 1;
    }
  }
  if (bad) {
    throw new KmsError(ErrorCode.DECRYPT_FAILED, 'invalid PKCS#7 padding');
  }
  return data.subarray(0, data.length - pad);
}

/**
 * @param {string} encodedText Base64(IV || ciphertext)
 * @param {'AES'|'SM4'} type
 * @param {'CBC'|'CTR'} mode
 * @param {Buffer} key 16-byte data key
 * @returns {Buffer}
 */
function decryptSymmetric(encodedText, type, mode, key) {
  const name = CIPHERS[type][mode];
  if (!crypto.getCiphers().includes(name)) {
    throw new KmsError(
      ErrorCode.ALGORITHM_UNAVAILABLE,
      `${name} is not supported by the OpenSSL build used by this Node.js runtime`,
    );
  }

  const encrypted = decodeBase64(encodedText);
  if (!encrypted) {
    throw new KmsError(ErrorCode.DECRYPT_FAILED, 'ciphertext is not valid base64');
  }

  const validLength =
    mode === 'CBC'
      ? encrypted.length >= BLOCK_SIZE * 2 && encrypted.length % BLOCK_SIZE === 0
      : encrypted.length >= BLOCK_SIZE + 1;
  if (!validLength) {
    throw new KmsError(ErrorCode.DECRYPT_FAILED, 'invalid ciphertext length');
  }

  const iv = encrypted.subarray(0, BLOCK_SIZE);
  const body = encrypted.subarray(BLOCK_SIZE);

  let plaintext;
  try {
    const decipher = crypto.createDecipheriv(name, key, iv);
    decipher.setAutoPadding(false);
    plaintext = Buffer.concat([decipher.update(body), decipher.final()]);
  } catch (cause) {
    throw new KmsError(ErrorCode.DECRYPT_FAILED, `${type}-${mode} decryption failed`, { cause });
  }

  return mode === 'CBC' ? unpadPkcs7(plaintext) : plaintext;
}

module.exports = { decryptSymmetric, BLOCK_SIZE };
