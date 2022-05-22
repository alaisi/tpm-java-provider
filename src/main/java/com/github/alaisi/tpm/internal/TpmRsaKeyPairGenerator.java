package com.github.alaisi.tpm.internal;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class TpmRsaKeyPairGenerator extends KeyPairGeneratorSpi {

    private int keySize;

    @Override
    public void initialize(int keySize, SecureRandom ignored) {
        this.keySize = keySize;
    }

    @Override
    public KeyPair generateKeyPair() {
        return new KeyPair(
                new TpmRsaPublicKey(BigInteger.ZERO, BigInteger.ZERO),
                new TpmRsaPrivateKey(BigInteger.ZERO, BigInteger.ZERO));
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
    }

    static class TpmRsaPrivateKey extends TpmRsaPublicKey implements RSAPrivateKey {

        TpmRsaPrivateKey(BigInteger modulus, BigInteger publicExponent) {
            super(modulus, publicExponent);
        }

        @Override
        public BigInteger getPrivateExponent() {
            throw new UnsupportedOperationException();
        }
    }
}
