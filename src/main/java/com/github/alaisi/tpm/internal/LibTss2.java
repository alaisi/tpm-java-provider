package com.github.alaisi.tpm.internal;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;

import static java.lang.foreign.MemoryAddress.NULL;
import static java.lang.foreign.MemorySession.openImplicit;
import static java.lang.foreign.ValueLayout.*;

enum LibTss2 { ;

    private static final MethodHandle esysInitialize;
    private static final MethodHandle esysFinalize;
    private static final MethodHandle esysGetRandom;
    private static final MethodHandle esysFree;
    private static final MethodHandle tss2RcDecode;

    private static final int ESYS_TR_NONE = 0xfff;

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
                (short) count,
                randomPtr);
        if (rc != 0) {
            throw new SecurityException("esysGetRandom failed: " + tss2RcDecode(rc));
        }
        try (var random = raii(randomPtr.get(ADDRESS, 0))) {
            var bytes = new byte[count];
            for (var i = 0; i < bytes.length; i++) {
                bytes[i] = random.target().get(JAVA_BYTE, i);
            }
            return bytes;
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
    private static Ref<MemoryAddress> raii(MemoryAddress ptr) {
        return new Ref<>(ptr, () -> esysFree(ptr));
    }
    record Ref<T> (T target, Runnable destructor) implements AutoCloseable {
        @Override
        public void close() {
            destructor.run();
        }
    }
}
