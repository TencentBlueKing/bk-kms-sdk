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
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.engines.SM4Engine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests that pin SM4-CBC PKCS7 unpad behaviour: only {@code pad > data.length}
 * is rejected; {@code pad == 0} yields the original data untouched.
 */
class Sm4Test {

    private static final byte[] KEY = "0123456789ABCDEF".getBytes(StandardCharsets.UTF_8);

    /**
     * The SM4 decrypt path tolerates {@code pad == 0}, otherwise arbitrary
     * server responses whose last plaintext byte is {@code 0x00} would
     * incorrectly fail.
     */
    @Test
    void pkcs7_unpad_tolerates_pad_zero() {
        byte[] plaintext = new byte[16];
        for (int i = 0; i < 15; i++) {
            plaintext[i] = (byte) ('A' + i);
        }
        plaintext[15] = 0x00;

        String cipherB64 = encryptRawCbc(plaintext, KEY);
        byte[] decrypted = Sm4.decryptCbc(cipherB64, KEY);

        assertArrayEquals(plaintext, decrypted,
                "SM4 pad==0 must return the block untouched");
    }

    /**
     * Sanity: standard PKCS7 (pad in [1..16]) still round-trips correctly.
     */
    @Test
    void pkcs7_normal_round_trip_still_works() {
        byte[] plaintext = "hello, bk-kms java sdk!".getBytes(StandardCharsets.UTF_8);
        String cipherB64 = Sm4.encryptCbc(plaintext, KEY);
        assertArrayEquals(plaintext, Sm4.decryptCbc(cipherB64, KEY));
    }

    /**
     * A trailing byte declaring more padding than the plaintext block length
     * must be rejected.
     */
    @Test
    void pkcs7_pad_greater_than_length_is_rejected() {
        byte[] plaintext = new byte[16];
        for (int i = 0; i < 15; i++) {
            plaintext[i] = 0x01;
        }
        plaintext[15] = 0x20;

        String cipherB64 = encryptRawCbc(plaintext, KEY);
        KmsException ex = assertThrows(KmsException.class, () -> Sm4.decryptCbc(cipherB64, KEY));
        assertTrue(ex.getMessage().contains("invalid pkcs7 padding length"),
                "unexpected message: " + ex.getMessage());
    }

    /**
     * SM4-CBC with no padding, used to inject a controlled trailing byte
     * (including {@code 0x00}) so we can exercise the pad==0 branch.
     */
    private static String encryptRawCbc(byte[] plaintext, byte[] key) {
        byte[] iv = new byte[16];
        for (int i = 0; i < iv.length; i++) {
            iv[i] = (byte) i;
        }

        BufferedBlockCipher cipher = new BufferedBlockCipher(
                CBCBlockCipher.newInstance(new SM4Engine()));
        cipher.init(true, new ParametersWithIV(new KeyParameter(key), iv));

        byte[] out = new byte[cipher.getOutputSize(plaintext.length)];
        try {
            int written = cipher.processBytes(plaintext, 0, plaintext.length, out, 0);
            written += cipher.doFinal(out, written);
            if (written != out.length) {
                byte[] trimmed = new byte[written];
                System.arraycopy(out, 0, trimmed, 0, written);
                out = trimmed;
            }
        } catch (Exception e) {
            throw new IllegalStateException("sm4 raw cbc encrypt for test failed", e);
        }

        byte[] combined = new byte[iv.length + out.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(out, 0, combined, iv.length, out.length);
        return Base64.getEncoder().encodeToString(combined);
    }
}
