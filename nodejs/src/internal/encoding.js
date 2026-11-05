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

const BASE64_RE = /^[A-Za-z0-9+/]*={0,2}$/;
const PEM_RE = /-----BEGIN ([^\r\n-]*)-----([\s\S]*?)-----END \1-----/;

/**
 * Strict padded standard Base64, matching Go's base64.StdEncoding
 * (which ignores CR/LF). Node's Buffer decoder is lenient, so validate first.
 * Returns null on invalid input.
 */
function decodeBase64(value) {
  const s = value.replace(/[\r\n]/g, '');
  if (s.length % 4 !== 0 || !BASE64_RE.test(s)) {
    return null;
  }
  return Buffer.from(s, 'base64');
}

/** Returns the DER bytes of the first PEM block (label ignored, like Go's pem.Decode). */
function decodePem(text) {
  const match = PEM_RE.exec(text);
  if (!match) {
    return null;
  }
  return decodeBase64(match[2].replace(/\s/g, ''));
}

/** Decodes a Base64-encoded PEM private key into DER bytes, or null. */
function decodePrivateKey(privateKeyBase64) {
  const pem = decodeBase64(privateKeyBase64);
  return pem ? decodePem(pem.toString('latin1')) : null;
}

function readTlv(buf, offset) {
  if (offset + 2 > buf.length) {
    throw new Error('truncated DER');
  }
  const tag = buf[offset];
  let length = buf[offset + 1];
  let pos = offset + 2;
  if (length & 0x80) {
    const n = length & 0x7f;
    if (n === 0 || n > 4 || pos + n > buf.length || buf[pos] === 0) {
      throw new Error('invalid DER length');
    }
    length = 0;
    for (let i = 0; i < n; i++) {
      length = length * 256 + buf[pos++];
    }
    if (length < 0x80) {
      throw new Error('non-minimal DER length');
    }
  }
  if (pos + length > buf.length) {
    throw new Error('truncated DER');
  }
  return { tag, value: buf.subarray(pos, pos + length), end: pos + length };
}

/** Parses a single DER element that must span the whole buffer. */
function parseDer(buf, expectedTag) {
  const tlv = readTlv(buf, 0);
  if (tlv.end !== buf.length) {
    throw new Error('trailing DER data');
  }
  if (tlv.tag !== expectedTag) {
    throw new Error('unexpected DER tag');
  }
  return tlv;
}

/** Returns the child elements of a constructed DER value. */
function derChildren(value) {
  const out = [];
  let offset = 0;
  while (offset < value.length) {
    const child = readTlv(value, offset);
    out.push(child);
    offset = child.end;
  }
  return out;
}

/** Left-pads an unsigned big-endian integer to `size` bytes; null if too large. */
function toFixedBytes(bytes, size) {
  let start = 0;
  while (start < bytes.length - 1 && bytes[start] === 0) {
    start++;
  }
  const trimmed = bytes.subarray(start);
  if (trimmed.length > size) {
    return null;
  }
  const out = Buffer.alloc(size);
  trimmed.copy(out, size - trimmed.length);
  return out;
}

module.exports = { decodeBase64, decodePem, decodePrivateKey, parseDer, derChildren, toFixedBytes };
