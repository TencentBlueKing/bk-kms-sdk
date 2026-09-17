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

package com.tencent.bk.kms.internal.crypto.sm4;

import com.tencent.bk.kms.types.KmsException;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.engines.SM4Engine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.SICBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

/**
 * SM4 encryption / decryption helpers backed by BouncyCastle (including the
 * big-endian CTR counter increment).
 *
 * <p><b>Internal API.</b> Do not depend on this class from outside the SDK.
 */
public final class Sm4 {

    private static final int BLOCK_SIZE = 16;

    private Sm4() {
    }

    /**
     * Decrypts an SM4-CBC ciphertext. The input is a Base64 string carrying
     * {@code iv(16) || ciphertext}, with PKCS7 padding on the plaintext.
     *
     * <p>Uses {@code NoPadding} + a manual {@link #pkcs7Unpad(byte[])} step
     * whose rejection rule ({@code pad > data.length}) includes tolerance of
     * {@code pad == 0}.
     */
    public static byte[] decryptCbc(String encodedText, byte[] key) {
        byte[] encrypted = decodeBase64(encodedText);
        if (encrypted.length < BLOCK_SIZE * 2) {
            throw new KmsException("invalid data length");
        }
        byte[] iv = Arrays.copyOfRange(encrypted, 0, BLOCK_SIZE);
        byte[] ciphertext = Arrays.copyOfRange(encrypted, BLOCK_SIZE, encrypted.length);

        BufferedBlockCipher cipher = new BufferedBlockCipher(
                CBCBlockCipher.newInstance(new SM4Engine()));
        cipher.init(false, new ParametersWithIV(new KeyParameter(key), iv));
        byte[] padded = processCipher(cipher, ciphertext, "sm4 cbc decrypt");
        return pkcs7Unpad(padded);
    }

    /**
     * Encrypts a plaintext in SM4-CBC. Primarily used by unit tests.
     */
    public static String encryptCbc(byte[] plaintext, byte[] key) {
        byte[] iv = new byte[BLOCK_SIZE];
        new SecureRandom().nextBytes(iv);

        PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(
                CBCBlockCipher.newInstance(new SM4Engine()), new PKCS7Padding());
        cipher.init(true, new ParametersWithIV(new KeyParameter(key), iv));
        byte[] ciphertext = processCipher(cipher, plaintext, "sm4 cbc encrypt");

        byte[] combined = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(ciphertext, 0, combined, iv.length, ciphertext.length);
        return Base64.getEncoder().encodeToString(combined);
    }

    /**
     * Decrypts an SM4-CTR ciphertext. The input is a Base64 string carrying
     * {@code nonce(16) || ciphertext}. The counter increments big-endian.
     */
    public static byte[] decryptCtr(String encodedText, byte[] key) {
        byte[] encrypted = decodeBase64(encodedText);
        if (encrypted.length < BLOCK_SIZE + 1) {
            throw new KmsException("invalid data length");
        }
        byte[] nonce = Arrays.copyOfRange(encrypted, 0, BLOCK_SIZE);
        byte[] ciphertext = Arrays.copyOfRange(encrypted, BLOCK_SIZE, encrypted.length);

        BlockCipher sic = SICBlockCipher.newInstance(new SM4Engine());
        BufferedBlockCipher cipher = new BufferedBlockCipher(sic);
        cipher.init(false, new ParametersWithIV(new KeyParameter(key), nonce));
        return processCipher(cipher, ciphertext, "sm4 ctr decrypt");
    }

    /**
     * Encrypts a plaintext in SM4-CTR. Primarily used by unit tests.
     */
    public static String encryptCtr(byte[] plaintext, byte[] key) {
        byte[] nonce = new byte[BLOCK_SIZE];
        new SecureRandom().nextBytes(nonce);

        BlockCipher sic = SICBlockCipher.newInstance(new SM4Engine());
        BufferedBlockCipher cipher = new BufferedBlockCipher(sic);
        cipher.init(true, new ParametersWithIV(new KeyParameter(key), nonce));
        byte[] ciphertext = processCipher(cipher, plaintext, "sm4 ctr encrypt");

        byte[] combined = new byte[nonce.length + ciphertext.length];
        System.arraycopy(nonce, 0, combined, 0, nonce.length);
        System.arraycopy(ciphertext, 0, combined, nonce.length, ciphertext.length);
        return Base64.getEncoder().encodeToString(combined);
    }

    private static byte[] processCipher(BufferedBlockCipher cipher, byte[] input, String op) {
        try {
            byte[] out = new byte[cipher.getOutputSize(input.length)];
            int written = cipher.processBytes(input, 0, input.length, out, 0);
            written += cipher.doFinal(out, written);
            if (written == out.length) {
                return out;
            }
            return Arrays.copyOf(out, written);
        } catch (Exception e) {
            throw new KmsException(op + " error(" + e.getMessage() + ")", e);
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
     * Values of {@code 0} are tolerated.
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
