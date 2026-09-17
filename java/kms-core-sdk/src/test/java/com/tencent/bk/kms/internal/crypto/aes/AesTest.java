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
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Tests that pin AES-CBC PKCS7 unpad behaviour: only {@code pad > data.length}
 * is rejected; {@code pad == 0} yields the original data untouched.
 */
class AesTest {

    private static final byte[] KEY = "0123456789ABCDEF".getBytes(StandardCharsets.UTF_8);

    /**
     * The unpad step must not reject {@code pad == 0}: it simply strips zero
     * bytes and returns the input unchanged. This is the observable behaviour
     * when decrypting arbitrary server payloads whose last plaintext byte
     * happens to be {@code 0x00}.
     */
    @Test
    void pkcs7_unpad_tolerates_pad_zero() throws Exception {
        // Craft a 16-byte plaintext whose last byte is 0x00 so that unpad sees pad == 0.
        byte[] plaintext = new byte[16];
        for (int i = 0; i < 15; i++) {
            plaintext[i] = (byte) ('A' + i);
        }
        plaintext[15] = 0x00;

        String cipherB64 = encryptRawCbc(plaintext, KEY);
        byte[] decrypted = Aes.decryptCbc(cipherB64, KEY);

        // With pad == 0 the whole 16-byte block is returned untouched.
        assertArrayEquals(plaintext, decrypted,
                "AES pad==0 must return the block untouched");
    }

    /**
     * Sanity: a normal round-trip through {@link Aes#encryptCbc(byte[], byte[])}
     * (which emits standard PKCS7 padding with pad in [1..16]) must still work.
     */
    @Test
    void pkcs7_normal_round_trip_still_works() {
        byte[] plaintext = "hello, bk-kms java sdk!".getBytes(StandardCharsets.UTF_8);
        String cipherB64 = Aes.encryptCbc(plaintext, KEY);
        assertArrayEquals(plaintext, Aes.decryptCbc(cipherB64, KEY));
    }

    /**
     * When the trailing byte declares more padding than the plaintext block
     * length, the payload must be rejected.
     */
    @Test
    void pkcs7_pad_greater_than_length_is_rejected() throws Exception {
        // Trailing byte = 0x20 (32) which exceeds the 16-byte block length.
        byte[] plaintext = new byte[16];
        for (int i = 0; i < 15; i++) {
            plaintext[i] = 0x01;
        }
        plaintext[15] = 0x20;

        String cipherB64 = encryptRawCbc(plaintext, KEY);
        KmsException ex = assertThrows(KmsException.class, () -> Aes.decryptCbc(cipherB64, KEY));
        assertEquals(true, ex.getMessage().contains("invalid pkcs7 padding length"),
                "unexpected message: " + ex.getMessage());
    }

    /**
     * Encrypt a plaintext whose length is a multiple of the block size using
     * AES-CBC with {@code NoPadding}, so that the ciphertext round-trips to the
     * exact plaintext we chose (allowing us to inject a trailing {@code 0x00}
     * to hit the {@code pad == 0} branch of the unpad routine).
     */
    private static String encryptRawCbc(byte[] plaintext, byte[] key) throws Exception {
        byte[] iv = new byte[16];
        for (int i = 0; i < iv.length; i++) {
            iv[i] = (byte) i;
        }
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        byte[] ciphertext = cipher.doFinal(plaintext);

        byte[] combined = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(ciphertext, 0, combined, iv.length, ciphertext.length);
        return Base64.getEncoder().encodeToString(combined);
    }
}
