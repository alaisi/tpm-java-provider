package com.github.alaisi.tpm.internal;

import java.math.BigInteger;
import java.security.Key;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HexFormat;

abstract sealed class TpmKey implements Key
        permits TpmKey.TpmRsaPrivateKey, TpmKey.TpmRsaPublicKey {

    @Override
    public String getFormat() {
        return "TPM";
    }

    @Override
    public byte[] getEncoded() {
        throw new UnsupportedOperationException();
    }

    static final class TpmRsaPublicKey extends TpmKey implements RSAPublicKey {

        private final BigInteger modulus;
        private final BigInteger publicExponent;

        TpmRsaPublicKey(BigInteger modulus, BigInteger publicExponent) {
            this.modulus = modulus;
            this.publicExponent = publicExponent;
        }

        @Override
        public String getAlgorithm() {
            return "RSA";
        }

        @Override
        public BigInteger getModulus() {
            return modulus;
        }

        @Override
        public BigInteger getPublicExponent() {
            return publicExponent;
        }

        @Override
        public String toString() {
            return String.format("TpmRsaPublicKey(publicExponent=%s, modulus=%s)", publicExponent, modulus);
        }
    }

    static final class TpmRsaPrivateKey extends TpmKey implements RSAPrivateKey {

        private final BigInteger modulus;
        private final byte[] marshalledPrivate;
        private final byte[] marshalledPublic;

        TpmRsaPrivateKey(BigInteger modulus, byte[] marshalledPrivate, byte[] marshalledPublic) {
            this.modulus = modulus;
            this.marshalledPrivate = marshalledPrivate;
            this.marshalledPublic = marshalledPublic;
        }

        @Override
        public String getAlgorithm() {
            return "RSA";
        }

        @Override
        public BigInteger getModulus() {
            return modulus;
        }

        @Override
        public BigInteger getPrivateExponent() {
            throw new UnsupportedOperationException();
        }

        @Override
        public String toString() {
            return String.format(
                    "TpmRsaPrivateKey(private=%s,public=%s)",
                    HexFormat.of().formatHex(marshalledPrivate),
                    HexFormat.of().formatHex(marshalledPublic));
        }

        byte[] getMarshalledPublic() {
            return marshalledPublic;
        }

        byte[] getMarshalledPrivate() {
            return marshalledPrivate;
        }
    }
}
