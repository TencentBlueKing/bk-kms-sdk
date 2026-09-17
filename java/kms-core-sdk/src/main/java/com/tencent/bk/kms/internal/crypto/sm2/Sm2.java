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

package com.tencent.bk.kms.internal.crypto.sm2;

import com.tencent.bk.kms.internal.crypto.KeyPair;
import com.tencent.bk.kms.types.KmsException;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.io.StringReader;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * SM2 helper. Ciphertext format is ASN.1 DER {@code SEQUENCE { X, Y, hash, cipher }}
 * (C1C3C2), matching {@code tjfoc/gmsm}'s {@code EncryptAsn1 / DecryptAsn1}.
 *
 * <p><b>Internal API.</b> Do not depend on this class from outside the SDK.
 */
public final class Sm2 {

    private static final X9ECParameters SM2_PARAMS = GMNamedCurves.getByName("sm2p256v1");
    private static final ECDomainParameters SM2_DOMAIN = new ECDomainParameters(
            SM2_PARAMS.getCurve(), SM2_PARAMS.getG(), SM2_PARAMS.getN(), SM2_PARAMS.getH());

    private static final int DIGEST_LENGTH = 32; // SM3 digest length

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private Sm2() {
    }

    /**
     * Generates a fresh SM2 key pair. Public/private keys are PEM encoded and
     * further Base64-wrapped so they can be transported as plain strings.
     */
    public static KeyPair generateKeyPair() {
        try {
            ECKeyPairGenerator generator = new ECKeyPairGenerator();
            generator.init(new ECKeyGenerationParameters(SM2_DOMAIN, new SecureRandom()));
            AsymmetricCipherKeyPair pair = generator.generateKeyPair();

            ECPublicKeyParameters pubParams = (ECPublicKeyParameters) pair.getPublic();
            ECPrivateKeyParameters privParams = (ECPrivateKeyParameters) pair.getPrivate();

            // Convert BC lightweight params to JCA keys using BC provider.
            KeyFactory factory = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
            java.security.spec.ECParameterSpec jcaEcSpec = ecParamSpec();

            java.security.spec.ECPoint jcaPoint = new java.security.spec.ECPoint(
                    pubParams.getQ().normalize().getAffineXCoord().toBigInteger(),
                    pubParams.getQ().normalize().getAffineYCoord().toBigInteger());
            PublicKey publicKey = factory.generatePublic(
                    new java.security.spec.ECPublicKeySpec(jcaPoint, jcaEcSpec));
            PrivateKey privateKey = factory.generatePrivate(
                    new java.security.spec.ECPrivateKeySpec(privParams.getD(), jcaEcSpec));

            String publicPem = toPem("PUBLIC KEY", publicKey.getEncoded());
            String privatePem = toPem("PRIVATE KEY", privateKey.getEncoded());
            return new KeyPair(
                    Base64.getEncoder().encodeToString(publicPem.getBytes(StandardCharsets.UTF_8)),
                    Base64.getEncoder().encodeToString(privatePem.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new KmsException("generate sm2 key pair error(" + e.getMessage() + ")", e);
        }
    }

    /**
     * Encrypts raw plaintext bytes with the Base64-of-PEM SM2 public key,
     * producing an ASN.1 C1C3C2 ciphertext (Base64 encoded). Prefer this
     * method for binary payloads such as symmetric keys.
     */
    public static String encryptBytes(byte[] plaintext, String publicKeyBase64) {
        try {
            String pem = new String(Base64.getDecoder().decode(publicKeyBase64), StandardCharsets.UTF_8);
            ECPublicKeyParameters pubParams = parsePublicKey(pem);

            SM2Engine engine = new SM2Engine(SM2Engine.Mode.C1C3C2);
            engine.init(true, new ParametersWithRandom(pubParams, new SecureRandom()));
            byte[] rawCipher = engine.processBlock(plaintext, 0, plaintext.length);

            // rawCipher layout: 0x04 || X(32) || Y(32) || C3(32) || C2(len).
            byte[] asn1 = rawC1C3C2ToAsn1(rawCipher);
            return Base64.getEncoder().encodeToString(asn1);
        } catch (Exception e) {
            throw new KmsException("sm2 encrypt error(" + e.getMessage() + ")", e);
        }
    }

    /**
     * Encrypts a UTF-8 string plaintext. Primarily used by unit tests.
     */
    public static String encrypt(String plaintext, String publicKeyBase64) {
        return encryptBytes(plaintext.getBytes(StandardCharsets.UTF_8), publicKeyBase64);
    }

    /**
     * Decrypts an ASN.1 C1C3C2 SM2 ciphertext (Base64 encoded) with the
     * Base64-of-PEM SM2 private key, returning the raw plaintext bytes.
     *
     * <p>Prefer this method when the plaintext is binary (e.g. a symmetric
     * key). Applying UTF-8 decoding to binary data corrupts it, because any
     * malformed byte sequence is silently replaced with U+FFFD.
     */
    public static byte[] decryptToBytes(String encodedText, String privateKeyBase64) {
        try {
            byte[] asn1 = Base64.getDecoder().decode(encodedText);
            String pem = new String(Base64.getDecoder().decode(privateKeyBase64), StandardCharsets.UTF_8);
            ECPrivateKeyParameters privParams = parsePrivateKey(pem);

            byte[] rawCipher = asn1C1C3C2ToRaw(asn1);
            SM2Engine engine = new SM2Engine(SM2Engine.Mode.C1C3C2);
            engine.init(false, privParams);
            return engine.processBlock(rawCipher, 0, rawCipher.length);
        } catch (Exception e) {
            throw new KmsException("sm2 decrypt error(" + e.getMessage() + ")", e);
        }
    }

    /**
     * Decrypts an ASN.1 C1C3C2 SM2 ciphertext (Base64 encoded) into a UTF-8
     * string. Only use this when the plaintext is known to be valid UTF-8;
     * for binary payloads use {@link #decryptToBytes(String, String)}.
     */
    public static String decrypt(String encodedText, String privateKeyBase64) {
        return new String(decryptToBytes(encodedText, privateKeyBase64), StandardCharsets.UTF_8);
    }

    private static byte[] rawC1C3C2ToAsn1(byte[] raw) throws Exception {
        // raw = 0x04 || X(32) || Y(32) || C3(32) || C2(rest)
        int coordLen = 32;
        int offset = 1; // skip 0x04
        BigInteger x = new BigInteger(1, sub(raw, offset, coordLen));
        offset += coordLen;
        BigInteger y = new BigInteger(1, sub(raw, offset, coordLen));
        offset += coordLen;
        byte[] c3 = sub(raw, offset, DIGEST_LENGTH);
        offset += DIGEST_LENGTH;
        byte[] c2 = sub(raw, offset, raw.length - offset);

        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(x));
        v.add(new ASN1Integer(y));
        v.add(new DEROctetString(c3));
        v.add(new DEROctetString(c2));
        return new DERSequence(v).getEncoded("DER");
    }

    private static byte[] asn1C1C3C2ToRaw(byte[] asn1Bytes) throws Exception {
        try (ASN1InputStream in = new ASN1InputStream(asn1Bytes)) {
            ASN1Sequence seq = (ASN1Sequence) in.readObject();
            BigInteger x = ((ASN1Integer) seq.getObjectAt(0)).getValue();
            BigInteger y = ((ASN1Integer) seq.getObjectAt(1)).getValue();
            byte[] c3 = ((ASN1OctetString) seq.getObjectAt(2)).getOctets();
            byte[] c2 = ((ASN1OctetString) seq.getObjectAt(3)).getOctets();

            byte[] xBytes = fixedLength(x, 32);
            byte[] yBytes = fixedLength(y, 32);

            byte[] raw = new byte[1 + xBytes.length + yBytes.length + c3.length + c2.length];
            raw[0] = 0x04;
            int p = 1;
            System.arraycopy(xBytes, 0, raw, p, xBytes.length);
            p += xBytes.length;
            System.arraycopy(yBytes, 0, raw, p, yBytes.length);
            p += yBytes.length;
            System.arraycopy(c3, 0, raw, p, c3.length);
            p += c3.length;
            System.arraycopy(c2, 0, raw, p, c2.length);
            return raw;
        }
    }

    private static byte[] fixedLength(BigInteger value, int length) {
        byte[] raw = value.toByteArray();
        if (raw.length == length) {
            return raw;
        }
        if (raw.length > length) {
            // strip leading zero sign byte
            byte[] trimmed = new byte[length];
            System.arraycopy(raw, raw.length - length, trimmed, 0, length);
            return trimmed;
        }
        byte[] padded = new byte[length];
        System.arraycopy(raw, 0, padded, length - raw.length, raw.length);
        return padded;
    }

    private static byte[] sub(byte[] src, int offset, int len) {
        byte[] out = new byte[len];
        System.arraycopy(src, offset, out, 0, len);
        return out;
    }

    private static ECPublicKeyParameters parsePublicKey(String pem) throws Exception {
        try (PEMParser parser = new PEMParser(new StringReader(pem))) {
            Object obj = parser.readObject();
            if (!(obj instanceof SubjectPublicKeyInfo spki)) {
                throw new KmsException("decode pem sm2 public key error");
            }
            KeyFactory factory = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
            PublicKey pub = factory.generatePublic(new X509EncodedKeySpec(spki.getEncoded()));
            ECPublicKey ecPub = (ECPublicKey) pub;

            ECPoint q = SM2_PARAMS.getCurve().createPoint(
                    ecPub.getW().getAffineX(), ecPub.getW().getAffineY());
            return new ECPublicKeyParameters(q, SM2_DOMAIN);
        }
    }

    private static ECPrivateKeyParameters parsePrivateKey(String pem) throws Exception {
        try (PEMParser parser = new PEMParser(new StringReader(pem))) {
            Object obj = parser.readObject();
            PrivateKey pk;
            if (obj instanceof PrivateKeyInfo pki) {
                KeyFactory factory = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
                pk = factory.generatePrivate(new PKCS8EncodedKeySpec(pki.getEncoded()));
            } else if (obj instanceof org.bouncycastle.openssl.PEMKeyPair pemPair) {
                JcaPEMKeyConverter conv = new JcaPEMKeyConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME);
                pk = conv.getPrivateKey(pemPair.getPrivateKeyInfo());
            } else {
                throw new KmsException("decode pem sm2 private key error");
            }
            ECPrivateKey ecPk = (ECPrivateKey) pk;
            return new ECPrivateKeyParameters(ecPk.getS(), SM2_DOMAIN);
        }
    }

    private static java.security.spec.ECParameterSpec ecParamSpec() {
        org.bouncycastle.jce.spec.ECNamedCurveParameterSpec bcSpec =
                org.bouncycastle.jce.ECNamedCurveTable.getParameterSpec("sm2p256v1");
        // BouncyCastle -> JCA ECParameterSpec conversion via helper.
        java.security.spec.EllipticCurve curve =
                org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util.convertCurve(
                        bcSpec.getCurve(), bcSpec.getSeed());
        java.security.spec.ECPoint g = new java.security.spec.ECPoint(
                bcSpec.getG().normalize().getAffineXCoord().toBigInteger(),
                bcSpec.getG().normalize().getAffineYCoord().toBigInteger());
        return new java.security.spec.ECParameterSpec(curve, g, bcSpec.getN(), bcSpec.getH().intValue());
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
