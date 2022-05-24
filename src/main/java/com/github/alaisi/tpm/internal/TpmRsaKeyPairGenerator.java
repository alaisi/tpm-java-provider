package com.github.alaisi.tpm.internal;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.MemorySession;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HexFormat;

public class TpmRsaKeyPairGenerator extends KeyPairGeneratorSpi {

    private short keySize;

    @Override
    public void initialize(int keySize, SecureRandom ignored) {
        this.keySize = (short) keySize;
    }

    @Override
    public KeyPair generateKeyPair() {
        try (var allocator = MemorySession.openConfined();
             var esysCtx = LibTss2.esysInitialize(allocator);
             var primaryCtx = LibTss2.esysCreatePrimary(allocator, esysCtx);
             var keys = LibTss2.esysCreateRsa(allocator, esysCtx, primaryCtx.target(), keySize)) {
            return new KeyPair(
                    new TpmRsaPublicKey(keys.target().modulus(), keys.target().publicExponent()),
                    new TpmRsaPrivateKey(keys.target().modulus(), keys.target().privateBuffer()));
        }
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
        private final byte[] privateBuffer;

        TpmRsaPrivateKey(BigInteger modulus, byte[] privateBuffer) {
            this.modulus = modulus;
            this.privateBuffer = privateBuffer;
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
            return String.format("TpmRsaPrivateKey(privateBuffer=%s)", HexFormat.of().formatHex(privateBuffer));
        }
    }
}
