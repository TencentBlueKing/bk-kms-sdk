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
const { decodeBase64, decodePrivateKey } = require('./encoding');

function parseKey(der, type) {
  try {
    return crypto.createPrivateKey({ key: der, format: 'der', type });
  } catch {
    return null;
  }
}

/** RSA-OAEP (SHA-256, MGF1-SHA-256, no label). Accepts PKCS#8 or PKCS#1 keys. */
function rsaDecrypt(encodedText, privateKeyBase64) {
  const ciphertext = decodeBase64(encodedText);
  if (!ciphertext) {
    throw new KmsError(ErrorCode.DECRYPT_FAILED, 'RSA encrypted key is not valid base64');
  }

  const der = decodePrivateKey(privateKeyBase64);
  if (!der) {
    throw new KmsError(ErrorCode.INVALID_PRIVATE_KEY, 'private key is not a base64-encoded PEM');
  }

  const key = parseKey(der, 'pkcs8') || parseKey(der, 'pkcs1');
  if (!key || key.asymmetricKeyType !== 'rsa') {
    throw new KmsError(ErrorCode.INVALID_PRIVATE_KEY, 'private key is not an RSA PKCS#8 or PKCS#1 key');
  }

  try {
    return crypto.privateDecrypt(
      { key, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
      ciphertext,
    );
  } catch (cause) {
    throw new KmsError(ErrorCode.DECRYPT_FAILED, 'RSA decryption failed', { cause });
  }
}

module.exports = { rsaDecrypt };
