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

package com.tencent.bk.kms.internal.crypto.rsa;

import com.tencent.bk.kms.internal.crypto.KeyPair;
import com.tencent.bk.kms.types.KmsException;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMParser;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * RSA-2048 key pair generation and OAEP-SHA256 decryption helpers (PKIX/PEM
 * public key, PKCS#1/PEM private key, both Base64).
 *
 * <p><b>Internal API.</b> Do not depend on this class from outside the SDK.
 */
public final class Rsa {

    private static final int DEFAULT_KEY_BITS = 2048;

    private Rsa() {
    }

    /**
     * Generates a fresh RSA-2048 key pair. Public key is PKIX/PEM, private key
     * is PKCS#1/PEM; both are then Base64-encoded so they can be transported as
     * plain strings.
     */
    public static KeyPair generateKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(DEFAULT_KEY_BITS);
            java.security.KeyPair pair = generator.generateKeyPair();

            String publicPem = toPem("PUBLIC KEY", pair.getPublic().getEncoded());

            RSAPrivateCrtKey crt = (RSAPrivateCrtKey) pair.getPrivate();
            RSAPrivateKey pkcs1 = new RSAPrivateKey(
                    crt.getModulus(), crt.getPublicExponent(), crt.getPrivateExponent(),
                    crt.getPrimeP(), crt.getPrimeQ(),
                    crt.getPrimeExponentP(), crt.getPrimeExponentQ(),
                    crt.getCrtCoefficient());
            String privatePem = toPem("RSA PRIVATE KEY", pkcs1.getEncoded("DER"));

            String publicB64 = Base64.getEncoder().encodeToString(publicPem.getBytes(StandardCharsets.UTF_8));
            String privateB64 = Base64.getEncoder().encodeToString(privatePem.getBytes(StandardCharsets.UTF_8));
            return new KeyPair(publicB64, privateB64);
        } catch (Exception e) {
            throw new KmsException("generate rsa key pair error(" + e.getMessage() + ")", e);
        }
    }

    /**
     * Decrypts an RSA-OAEP(SHA-256, MGF1(SHA-256)) ciphertext, returning the
     * raw plaintext bytes. Accepts a Base64-of-PEM private key
     * (either PKCS#8 or PKCS#1).
     *
     * <p>Prefer this method when the plaintext is binary (e.g. a symmetric
     * key). Applying UTF-8 decoding to binary data corrupts it, because any
     * malformed byte sequence is silently replaced with U+FFFD.
     */
    public static byte[] decryptToBytes(String encodedText, String privateKeyBase64) {
        try {
            byte[] ciphertext = Base64.getDecoder().decode(encodedText);
            String pem = new String(Base64.getDecoder().decode(privateKeyBase64), StandardCharsets.UTF_8);

            PrivateKey privateKey = parsePrivateKey(pem);

            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
            OAEPParameterSpec spec = new OAEPParameterSpec(
                    "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
            cipher.init(Cipher.DECRYPT_MODE, privateKey, spec);
            return cipher.doFinal(ciphertext);
        } catch (Exception e) {
            throw new KmsException("rsa decrypt error(" + e.getMessage() + ")", e);
        }
    }

    /**
     * Decrypts an RSA-OAEP(SHA-256, MGF1(SHA-256)) ciphertext into a UTF-8
     * string. Only use this when the plaintext is known to be valid UTF-8;
     * for binary payloads use {@link #decryptToBytes(String, String)}.
     */
    public static String decrypt(String encodedText, String privateKeyBase64) {
        return new String(decryptToBytes(encodedText, privateKeyBase64), StandardCharsets.UTF_8);
    }

    /**
     * Encrypts raw plaintext bytes with the given Base64-of-PEM public key
     * using RSA-OAEP(SHA-256). Prefer this method for binary payloads such as
     * symmetric keys.
     */
    public static String encryptBytes(byte[] plaintext, String publicKeyBase64) {
        try {
            String pem = new String(Base64.getDecoder().decode(publicKeyBase64), StandardCharsets.UTF_8);
            PublicKey publicKey = parsePublicKey(pem);

            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
            OAEPParameterSpec spec = new OAEPParameterSpec(
                    "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey, spec);
            byte[] ciphertext = cipher.doFinal(plaintext);
            return Base64.getEncoder().encodeToString(ciphertext);
        } catch (Exception e) {
            throw new KmsException("rsa encrypt error(" + e.getMessage() + ")", e);
        }
    }

    /**
     * Encrypts a UTF-8 string plaintext. Primarily used by unit tests.
     */
    public static String encrypt(String plaintext, String publicKeyBase64) {
        return encryptBytes(plaintext.getBytes(StandardCharsets.UTF_8), publicKeyBase64);
    }

    private static PrivateKey parsePrivateKey(String pem) throws Exception {
        try (PEMParser parser = new PEMParser(new StringReader(pem))) {
            Object obj = parser.readObject();
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            if (obj instanceof PrivateKeyInfo pki) {
                // PKCS#8 encoded.
                return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(pki.getEncoded()));
            }
            if (obj instanceof org.bouncycastle.openssl.PEMKeyPair pemPair) {
                // PKCS#1 encoded (traditional OpenSSL "RSA PRIVATE KEY").
                PrivateKeyInfo pki = pemPair.getPrivateKeyInfo();
                return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(pki.getEncoded()));
            }
            throw new KmsException("decode pem private key error");
        }
    }

    private static PublicKey parsePublicKey(String pem) throws Exception {
        try (PEMParser parser = new PEMParser(new StringReader(pem))) {
            Object obj = parser.readObject();
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            if (obj instanceof SubjectPublicKeyInfo spki) {
                return keyFactory.generatePublic(new X509EncodedKeySpec(spki.getEncoded()));
            }
            if (obj instanceof org.bouncycastle.asn1.pkcs.RSAPublicKey rsaPub) {
                // PKCS#1 "RSA PUBLIC KEY".
                java.security.spec.RSAPublicKeySpec spec = new java.security.spec.RSAPublicKeySpec(
                        rsaPub.getModulus(), rsaPub.getPublicExponent());
                return keyFactory.generatePublic(spec);
            }
            throw new KmsException("decode pem public key error");
        }
    }

    private static String toPem(String type, byte[] der) {
        String base64 = Base64.getEncoder().encodeToString(der);
        StringBuilder builder = new StringBuilder();
        builder.append("-----BEGIN ").append(type).append("-----\n");
        for (int i = 0; i < base64.length(); i += 64) {
            builder.append(base64, i, Math.min(i + 64, base64.length())).append('\n');
        }
        builder.append("-----END ").append(type).append("-----\n");
        return builder.toString();
    }
}
