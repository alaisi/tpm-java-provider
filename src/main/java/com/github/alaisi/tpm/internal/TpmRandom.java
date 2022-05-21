package com.github.alaisi.tpm.internal;

import java.lang.foreign.MemorySession;
import java.security.SecureRandomSpi;

public class TpmRandom extends SecureRandomSpi {

    @Override
    protected void engineNextBytes(byte[] bytes) {
        try (var allocator = MemorySession.openConfined();
             var esysCtx = LibTss2.esysInitialize(allocator)) {
            var random = LibTss2.esysGetRandom(allocator, esysCtx, bytes.length);
            System.arraycopy(random, 0, bytes, 0, random.length);
        }
    }

    @Override
    protected byte[] engineGenerateSeed(int numBytes) {
        try (var allocator = MemorySession.openConfined();
             var esysCtx = LibTss2.esysInitialize(allocator)) {
            return LibTss2.esysGetRandom(allocator, esysCtx, numBytes);
        }
    }

    @Override
    protected void engineSetSeed(byte[] seed) { }
}
