package com.github.alaisi.tpm.internal;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;

import static java.lang.foreign.MemoryAddress.NULL;
import static java.lang.foreign.MemoryLayout.structLayout;
import static java.lang.foreign.MemoryLayout.unionLayout;
import static java.lang.foreign.MemorySession.openImplicit;
import static java.lang.foreign.ValueLayout.*;

enum LibTss2 { ;

    private static final MethodHandle esysInitialize;
    private static final MethodHandle esysFinalize;
    private static final MethodHandle esysGetRandom;
    private static final MethodHandle esysStirRandom;
    private static final MethodHandle esysFree;
    private static final MethodHandle tss2RcDecode;

    private static final int ESYS_TR_NONE = 0xfff;

    private enum Tpm2bDigest { ;
        static final MemoryLayout struct = structLayout(
                JAVA_SHORT.withName("size"),
                MemoryLayout.sequenceLayout(64, JAVA_BYTE).withName("buffer"));
        static final VarHandle size = struct.varHandle(
                PathElement.groupElement("size"));
        static final VarHandle buffer = struct.varHandle(
                PathElement.groupElement("buffer"),
                PathElement.sequenceElement());

        static MemorySegment at(MemoryAddress address, MemorySession allocator) {
            return MemorySegment.ofAddress(address, struct.byteSize(), allocator);
        }
    }

    private enum Tpm2bSensitiveData { ;
        static final MemoryLayout struct = structLayout(
                JAVA_SHORT.withName("size"),
                MemoryLayout.sequenceLayout(256, JAVA_BYTE).withName("buffer"));
        static final VarHandle size = struct.varHandle(
                PathElement.groupElement("size"));
        static final VarHandle buffer = struct.varHandle(
                PathElement.groupElement("buffer"),
                PathElement.sequenceElement());
    }

    private enum TpmSKeyedHashParms { ;
        static final MemoryLayout struct = structLayout(
                structLayout(
                        JAVA_SHORT.withName("scheme"),
                        unionLayout(
                                structLayout(
                                        JAVA_SHORT.withName("hashAlg")
                                ).withName("hmac"),
                                structLayout(
                                        JAVA_SHORT.withName("hashAlg"),
                                        JAVA_SHORT.withName("kdf")
                                ).withName("exclusiveOr")
                        ).withName("details")
                ).withName("scheme"));
    }

    private enum TpmSSymCipherParms { ;
        static final MemoryLayout struct = structLayout(
                structLayout(
                        JAVA_SHORT.withName("algorithm"),
                        JAVA_SHORT.withName("keyBits"),
                        JAVA_SHORT.withName("mode")
                ).withName("sym")
        );
    }

    private enum TpmUPublicParms { ;
        static final MemoryLayout union = unionLayout(
                TpmSKeyedHashParms.struct.withName("keyedHashDetail"),
                TpmSSymCipherParms.struct.withName("symDetail")
                // TPMS_RSA_PARMS rsaDetail
                // TPMS_ECC_PARMS eccDetail
                // TPMS_ASYM_PARMS asymDetail
        );
    }
    private enum Tpm2bPublic { ;
        static final MemoryLayout struct = structLayout(
                JAVA_SHORT.withName("size"),
                structLayout(
                        JAVA_SHORT.withName("type"),
                        JAVA_SHORT.withName("nameAlg"),
                        JAVA_INT.withName("objectAttributes"),
                        Tpm2bDigest.struct.withName("authPolicy"),
                        unionLayout(

                        ).withName("parameters"),
                        unionLayout(
                                Tpm2bDigest.struct.withName("keyedHash"),
                                Tpm2bDigest.struct.withName("sym"),
                                structLayout(
                                        JAVA_SHORT.withName("size"),
                                        MemoryLayout.sequenceLayout(512, JAVA_BYTE).withName("buffer")
                                ).withName("rsa"),
                                structLayout(
                                        structLayout(
                                                JAVA_SHORT.withName("size"),
                                                MemoryLayout.sequenceLayout(128, JAVA_BYTE).withName("buffer")
                                        ).withName("x"),
                                        structLayout(
                                                JAVA_SHORT.withName("size"),
                                                MemoryLayout.sequenceLayout(128, JAVA_BYTE).withName("buffer")
                                        ).withName("y")
                                ).withName("ecc")
                        ).withName("unique")
                ));
    }

    static {
        var linker = Linker.nativeLinker();

        var libTss2Esys = SymbolLookup.libraryLookup("libtss2-esys.so", openImplicit());
        esysInitialize = linker.downcallHandle(
                libTss2Esys.lookup("Esys_Initialize").orElseThrow(),
                FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS, ADDRESS));
        esysFinalize = linker.downcallHandle(
                libTss2Esys.lookup("Esys_Finalize").orElseThrow(),
                FunctionDescriptor.ofVoid(ADDRESS));
        esysGetRandom = linker.downcallHandle(
                libTss2Esys.lookup("Esys_GetRandom").orElseThrow(),
                FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_INT, JAVA_INT, JAVA_INT, JAVA_SHORT, ADDRESS));
        esysStirRandom = linker.downcallHandle(
                libTss2Esys.lookup("Esys_StirRandom").orElseThrow(),
                FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_INT, JAVA_INT, JAVA_INT, ADDRESS));
        esysFree = linker.downcallHandle(
                libTss2Esys.lookup("Esys_Free").orElseThrow(),
                FunctionDescriptor.ofVoid(ADDRESS));

        var libTss2Rc = SymbolLookup.libraryLookup("libtss2-rc.so", openImplicit());
        tss2RcDecode = linker.downcallHandle(
                libTss2Rc.lookup("Tss2_RC_Decode").orElseThrow(),
                FunctionDescriptor.of(ADDRESS, JAVA_INT));
    }

    static Ref<MemoryAddress> esysInitialize(MemorySession allocator) {
        var esysCtxPtr = MemorySegment.allocateNative(ADDRESS, allocator);
        int rc = (int) invoke(esysInitialize, esysCtxPtr, NULL, NULL);
        if (rc != 0) {
            throw new SecurityException("esysInitialize failed: " + tss2RcDecode(rc));
        }
        return new Ref<>(
                esysCtxPtr.get(ADDRESS, 0),
                () -> invoke(esysFinalize, esysCtxPtr));
    }

    static byte[] esysGetRandom(MemorySession allocator, Ref<MemoryAddress> esysCtx, int count) {
        var randomPtr = MemorySegment.allocateNative(ADDRESS, allocator);
        int rc = (int) invoke(esysGetRandom, esysCtx.target(),
                ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                (short) Math.min(count, 64),
                randomPtr);
        if (rc != 0) {
            throw new SecurityException("esysGetRandom failed: " + tss2RcDecode(rc));
        }
        try (var random = asRef(randomPtr.get(ADDRESS, 0))) {
            var digest = Tpm2bDigest.at(random.target(), allocator);
            var bytes = new byte[(int) Tpm2bDigest.size.get(digest)];
            for (var i = 0; i < bytes.length; i++) {
                bytes[i] = (byte) Tpm2bDigest.buffer.get(digest, i);
            }
            return bytes;
        }
    }

    static void esysStirRandom(MemorySession allocator, Ref<MemoryAddress> esysCtx, byte[] seed) {
        var stir = MemorySegment.allocateNative(Tpm2bSensitiveData.struct, allocator);
        for (int i = 0; i < seed.length; i += 128) {
            var j = Math.min(i + 128, seed.length);
            Tpm2bSensitiveData.size.set(stir, (short) (j - i));
            for (int k = 0; k < j - i; k++) {
                Tpm2bSensitiveData.buffer.set(stir, k, seed[i + k]);
            }
        }

        int rc = (int) invoke(esysStirRandom, esysCtx.target(), ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, stir);
        if (rc != 0) {
            throw new SecurityException("esysStirRandom failed: " + tss2RcDecode(rc));
        }
    }

    static void esysFree(MemoryAddress ptr) {
        invoke(esysFree, ptr);
    }

    static String tss2RcDecode(int rc) {
        var err = (MemoryAddress) invoke(tss2RcDecode, rc);
        return err.getUtf8String(0);
    }

    private static Object invoke(MethodHandle methodHandle, Object... args) {
        try {
            return methodHandle.invokeWithArguments(args);
        } catch (Throwable t) {
            throw new RuntimeException(t);
        }
    }
    private static Ref<MemoryAddress> asRef(MemoryAddress ptr) {
        return new Ref<>(ptr, () -> esysFree(ptr));
    }
    record Ref<T> (T target, Runnable destructor) implements AutoCloseable {
        @Override
        public void close() {
            destructor.run();
        }
    }
}
