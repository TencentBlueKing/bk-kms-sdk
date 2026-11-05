/**
 * Error codes carried by {@link KmsError.code}.
 */
export declare const ErrorCode: {
  /** `envelope` or `privateKey` is not a non-empty string. */
  readonly INVALID_ARGUMENT: 'INVALID_ARGUMENT';
  /** The envelope is not Base64 JSON, or a required field is missing. */
  readonly INVALID_ENVELOPE: 'INVALID_ENVELOPE';
  /** The envelope names an unsupported algorithm or mode. */
  readonly UNSUPPORTED_ALGORITHM: 'UNSUPPORTED_ALGORITHM';
  /** The Node.js OpenSSL build lacks SM2/SM3/SM4 support. */
  readonly ALGORITHM_UNAVAILABLE: 'ALGORITHM_UNAVAILABLE';
  /** The private key cannot be parsed or does not match the algorithm. */
  readonly INVALID_PRIVATE_KEY: 'INVALID_PRIVATE_KEY';
  /** Decryption failed: mismatched key, corrupted data or bad padding. */
  readonly DECRYPT_FAILED: 'DECRYPT_FAILED';
  /** The decrypted plaintext is not valid UTF-8. */
  readonly INVALID_PLAINTEXT: 'INVALID_PLAINTEXT';
};

export type ErrorCode = (typeof ErrorCode)[keyof typeof ErrorCode];

/**
 * Error thrown by {@link decrypt}. Messages never contain the private key,
 * envelope, data key or plaintext.
 */
export declare class KmsError extends Error {
  readonly name: 'KmsError';
  readonly code: ErrorCode;
}

/**
 * Decrypts a Base64 JSON hybrid envelope with its matching Base64 PEM private key.
 *
 * @param envelope Base64-encoded envelope issued by BK-KMS.
 * @param privateKey Base64-encoded PEM private key (RSA PKCS#8/PKCS#1 or SM2 PKCS#8).
 * @returns The original UTF-8 plaintext.
 * @throws {KmsError}
 */
export declare function decrypt(envelope: string, privateKey: string): string;
