package com.github.alaisi.tpm.internal;

import com.github.alaisi.tpm.internal.TpmKey.TpmRsaPrivateKey;
import com.github.alaisi.tpm.internal.TpmKey.TpmRsaPublicKey;

import java.lang.foreign.MemorySession;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;

public final class TpmRsaKeyPairGenerator extends KeyPairGeneratorSpi {

    private short keySize;

    @Override
    public void initialize(int keySize, SecureRandom ignored) {
        this.keySize = (short) keySize;
    }

    @Override
    public KeyPair generateKeyPair() {
        try (var allocator = MemorySession.openConfined();
             var esysCtx = LibTss2.esysInitialize(allocator);
             var primaryCtx = LibTss2.esysCreatePrimary(allocator, esysCtx)) {
            var keys = LibTss2.esysCreateRsa(allocator, esysCtx, primaryCtx.target(), keySize);
            return new KeyPair(
                    new TpmRsaPublicKey(keys.modulus(), keys.publicExponent()),
                    new TpmRsaPrivateKey(keys.modulus(), keys.marshalledPrivate(), keys.marshalledPublic()));
        }
    }
}
