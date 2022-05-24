package com.github.alaisi.tpm.internal;

import java.lang.foreign.MemorySession;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HexFormat;

import static com.github.alaisi.tpm.internal.LibTss2.TPM2_ALG_RSA;

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
             var keys = LibTss2.esysCreate(
                     allocator, esysCtx, primaryCtx.target(), TPM2_ALG_RSA, keySize)) {
            return new KeyPair(
                    new TpmRsaPublicKey(keys.target().modulus(), keys.target().publicExponent()),
                    new TpmRsaPrivateKey(keys.target().modulus(), keys.target().publicExponent(), keys.target().privateBuffer()));
        }
    }

    static class TpmRsaPublicKey extends TpmKey implements RSAPublicKey {

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
            return String.format("TpmRsaPublicKey(modulus=%s, publicExponent=%s)", modulus, publicExponent);
        }
    }

    static class TpmRsaPrivateKey extends TpmRsaPublicKey implements RSAPrivateKey {

        private final byte[] tpmHandle;

        TpmRsaPrivateKey(BigInteger modulus, BigInteger publicExponent, byte[] tpmHandle) {
            super(modulus, publicExponent);
            this.tpmHandle = tpmHandle;
        }

        @Override
        public BigInteger getPrivateExponent() {
            throw new UnsupportedOperationException();
        }

        @Override
        public String toString() {
            return String.format("TpmRsaPrivateKey(tpmHandle=%s)", HexFormat.of().formatHex(tpmHandle));
        }
    }
}
