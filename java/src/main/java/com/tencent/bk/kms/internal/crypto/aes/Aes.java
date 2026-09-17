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

package com.tencent.bk.kms.internal.crypto.aes;

import com.tencent.bk.kms.types.KmsException;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;
import java.util.Base64;

/**
 * AES-128 encryption / decryption helpers.
 *
 * <p><b>Internal API.</b> Do not depend on this class from outside the SDK.
 */
public final class Aes {

    private static final int BLOCK_SIZE = 16;

    private Aes() {
    }

    /**
     * Decrypts an AES-128-CBC ciphertext. The input is a Base64 string carrying
     * {@code iv(16) || ciphertext}, with PKCS7 padding on the plaintext.
     */
    public static byte[] decryptCbc(String encodedText, byte[] key) {
        byte[] encrypted = decodeBase64(encodedText);
        if (encrypted.length < BLOCK_SIZE) {
            throw new KmsException("invalid data length");
        }

        byte[] iv = Arrays.copyOfRange(encrypted, 0, BLOCK_SIZE);
        byte[] ciphertext = Arrays.copyOfRange(encrypted, BLOCK_SIZE, encrypted.length);

        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
            byte[] padded = cipher.doFinal(ciphertext);
            return pkcs7Unpad(padded);
        } catch (KmsException e) {
            throw e;
        } catch (Exception e) {
            throw new KmsException("aes cbc decrypt error(" + e.getMessage() + ")", e);
        }
    }

    /**
     * Encrypts a plaintext in AES-128-CBC. A random IV is prepended before
     * Base64 encoding. Primarily used by unit tests.
     */
    public static String encryptCbc(byte[] plaintext, byte[] key) {
        try {
            byte[] iv = new byte[BLOCK_SIZE];
            java.security.SecureRandom.getInstanceStrong().nextBytes(iv);

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
            byte[] ciphertext = cipher.doFinal(plaintext);

            byte[] combined = new byte[iv.length + ciphertext.length];
            System.arraycopy(iv, 0, combined, 0, iv.length);
            System.arraycopy(ciphertext, 0, combined, iv.length, ciphertext.length);
            return Base64.getEncoder().encodeToString(combined);
        } catch (Exception e) {
            throw new KmsException("aes cbc encrypt error(" + e.getMessage() + ")", e);
        }
    }

    /**
     * Decrypts an AES-128-CTR ciphertext. The input is a Base64 string carrying
     * {@code nonce(16) || ciphertext}.
     */
    public static byte[] decryptCtr(String encodedText, byte[] key) {
        byte[] encrypted = decodeBase64(encodedText);
        if (encrypted.length < BLOCK_SIZE + 1) {
            throw new KmsException("invalid data length");
        }

        byte[] nonce = Arrays.copyOfRange(encrypted, 0, BLOCK_SIZE);
        byte[] ciphertext = Arrays.copyOfRange(encrypted, BLOCK_SIZE, encrypted.length);

        try {
            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(nonce));
            return cipher.doFinal(ciphertext);
        } catch (Exception e) {
            throw new KmsException("aes ctr decrypt error(" + e.getMessage() + ")", e);
        }
    }

    /**
     * Encrypts a plaintext in AES-128-CTR. Primarily used by unit tests.
     */
    public static String encryptCtr(byte[] plaintext, byte[] key) {
        try {
            byte[] nonce = new byte[BLOCK_SIZE];
            java.security.SecureRandom.getInstanceStrong().nextBytes(nonce);

            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(nonce));
            byte[] ciphertext = cipher.doFinal(plaintext);

            byte[] combined = new byte[nonce.length + ciphertext.length];
            System.arraycopy(nonce, 0, combined, 0, nonce.length);
            System.arraycopy(ciphertext, 0, combined, nonce.length, ciphertext.length);
            return Base64.getEncoder().encodeToString(combined);
        } catch (Exception e) {
            throw new KmsException("aes ctr encrypt error(" + e.getMessage() + ")", e);
        }
    }

    private static byte[] decodeBase64(String encodedText) {
        try {
            return Base64.getDecoder().decode(encodedText);
        } catch (IllegalArgumentException e) {
            throw new KmsException("base64 error(" + e.getMessage() + ")", e);
        }
    }

    /**
     * PKCS7 unpadding: the only rejection is {@code pad > data.length}.
     * Values of {@code 0} (or negative when interpreted as signed) are
     * tolerated.
     */
    private static byte[] pkcs7Unpad(byte[] data) {
        if (data.length == 0) {
            throw new KmsException("invalid pkcs7 data length");
        }
        int pad = data[data.length - 1] & 0xFF;
        if (pad > data.length) {
            throw new KmsException("invalid pkcs7 padding length");
        }
        return Arrays.copyOfRange(data, 0, data.length - pad);
    }
}
