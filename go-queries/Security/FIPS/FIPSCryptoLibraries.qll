/**
 * Adapted from the experimental CWE-327 CryptoLibraries for FIPS purposes
 * Currently, this only supports Go
 * Python is going to need its own class
 */

import go

module AlgorithmNames {
    predicate isApprovedHashingAlgorithm(string name) {
        name =
            [
                "SHA2", "SHA3", "HMAC", "SHA256", "SHA384", "SHA512", "ES256", "ES384",
                "DSA", "ECDSA", "ECDSA256", "ECDSA384", "ECDSA512", "ES512"
            ]
    }

    predicate isDisallowedHashingAlgorithm(string name) {
        name =
            [
                "BLAKE2B", "BLAKE2S", "CURVE25519", "ED25519", "MD2", "MD4",
                "MD5", "RIPEMD160", "SHA0", "SHA1", "SHA224", "HAVEL128",
                "PANAMA", "RIPEMD", "RIPEMD128", "RIPEMD256", "RIPEMD320"
            ]
    }

    predicate isApprovedEncryptionAlgorithm(string name) {
        name =
            [
                 "AES", "AES128", "AES192", "AES256", "RSA"
            ]
    }

    predicate isDisallowedEncryptionAlgorithm(string name) {
        name =
            [
                "BLOWFISH", "CAST5", "CHACHA20", "CHACHA20POLY1305", "OPENPGP",
                "OTR", "SALSA20", "TEA", "TWOFISH", "XTEA", "XTS", "RC4", "DES",
                "3DES", "RABBIT", "ARC5", "RC5", "TRIPLEDES", "TDEA", "TRIPLEDEA",
                "ARC2", "RC2", "ARC4", "ARCFOUR"

            ]
    }

    predicate isApprovedPasswordHashingAlgorithm(string name) {
        name =
            [
                "ARGON2", "PBKDF2", "BCRYPT", "SCRPYT"
            ]
    }

    predicate isDisallowedPasswordHashingAlgorithm(string name) {
        name =
            [
                "HKDF"
            ]
    }

    /**
     * Miscellaneous objects, including things like go crypto's subtle which
     * are not meant to be used by developers without careful thought or ambiguous
     * AES/SHA2 could be SHA2 at 224 bits, which is too weak
     */
    predicate isMiscellaneousToBeFlagged(string name) {
        name =
            [
                "NACL", "SSH", "RAND", "TLS", "SUBTLE", "X509"
            ]
    }
}