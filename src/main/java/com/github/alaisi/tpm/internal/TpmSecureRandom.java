package com.github.alaisi.tpm.internal;

import java.lang.foreign.MemorySession;
import java.security.SecureRandomSpi;

public final class TpmSecureRandom extends SecureRandomSpi {

    @Override
    protected void engineNextBytes(byte[] bytes) {
        try (var allocator = MemorySession.openConfined();
             var esysCtx = LibTss2.esysInitialize(allocator)) {
            for (var offset = 0; offset < bytes.length;) {
                var random = LibTss2.esysGetRandom(allocator, esysCtx, bytes.length - offset);
                System.arraycopy(random, 0, bytes, offset, Math.min(random.length, bytes.length - offset));
                offset += random.length;
            }
        }
    }

    @Override
    protected byte[] engineGenerateSeed(int numBytes) {
        var bytes = new byte[numBytes];
        engineNextBytes(bytes);
        return bytes;
    }

    @Override
    protected void engineSetSeed(byte[] seed) {
        try (var allocator = MemorySession.openConfined();
             var esysCtx = LibTss2.esysInitialize(allocator)) {
            LibTss2.esysStirRandom(allocator, esysCtx, seed);
        }
    }
}
