package com.github.alaisi.tpm.internal;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HexFormat;

import static com.github.alaisi.tpm.internal.LibTss2Types.*;
import static java.lang.foreign.MemoryAddress.NULL;
import static java.lang.foreign.MemorySession.openImplicit;
import static java.lang.foreign.ValueLayout.*;

enum LibTss2 { ;

    private static final MethodHandle esysInitialize;
    private static final MethodHandle esysFinalize;
    private static final MethodHandle esysGetRandom;
    private static final MethodHandle esysStirRandom;
    private static final MethodHandle esysFree;
    private static final MethodHandle tss2RcDecode;
    private static final MethodHandle esysCreatePrimary;
    private static final MethodHandle esysFlushContext;

    private static final int ESYS_TR_NONE = 0xfff;
    private static final int ESYS_TR_RH_OWNER = 0x101;
    private static final int ESYS_TR_PASSWORD = 0x0ff;
    private static final short TPM2_ALG_ECC = 0x0023;

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
        esysCreatePrimary = linker.downcallHandle(
                libTss2Esys.lookup("Esys_CreatePrimary").orElseThrow(),
                FunctionDescriptor.of(
                        JAVA_INT, ADDRESS, JAVA_INT, JAVA_INT, JAVA_INT, JAVA_INT,
                        ADDRESS, ADDRESS, ADDRESS, ADDRESS, ADDRESS, ADDRESS, ADDRESS, ADDRESS, ADDRESS));
        esysFlushContext = linker.downcallHandle(
                libTss2Esys.lookup("Esys_FlushContext").orElseThrow(),
                FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_INT));
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
            var digest = cast(random.target(), TPM2B_DIGEST, allocator);
            var bytes = new byte[(int) TPM2B_DIGEST_size.get(digest)];
            for (var i = 0; i < bytes.length; i++) {
                bytes[i] = (byte) TPM2B_DIGEST_buffer.get(digest, i);
            }
            return bytes;
        }
    }

    static void esysStirRandom(MemorySession allocator, Ref<MemoryAddress> esysCtx, byte[] seed) {
        var stir = MemorySegment.allocateNative(TPM2B_SENSITIVE_DATA, allocator);
        for (int i = 0; i < seed.length; i += 128) {
            var j = Math.min(i + 128, seed.length);
            TPM2B_SENSITIVE_DATA_size.set(stir, (short) (j - i));
            for (int k = 0; k < j - i; k++) {
                TPM2B_SENSITIVE_DATA_buffer.set(stir, k, seed[i + k]);
            }
        }

        int rc = (int) invoke(esysStirRandom, esysCtx.target(), ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, stir);
        if (rc != 0) {
            throw new SecurityException("esysStirRandom failed: " + tss2RcDecode(rc));
        }
    }

    static Ref<Integer> esysCreatePrimary(MemorySession allocator, Ref<MemoryAddress> esysCtx) {
        var inPublic = MemorySegment.allocateNative(TPM2B_PUBLIC, allocator);
        TPM2B_PUBLIC_publicArea_type.set(inPublic, TPM2_ALG_ECC);
        TPM2B_PUBLIC_publicArea_nameAlg.set(inPublic, (short) 0x000B);
        TPM2B_PUBLIC_publicArea_objectAttributes.set(inPublic, 0x00030472);
        TPM2B_PUBLIC_authPolicy_size.set(inPublic, (short) 0);
        TPM2B_PUBLIC_parameters_algorithm.set(inPublic, (short) 0x0006);
        TPM2B_PUBLIC_parameters_mode.set(inPublic, (short) 0x0043);
        TPM2B_PUBLIC_parameters_keyBits.set(inPublic, (short) 128);
        TPM2B_PUBLIC_parameters_scheme.set(inPublic, (short) 0x0010);
        TPM2B_PUBLIC_parameters_curveID.set(inPublic, (short) 0x0003);
        TPM2B_PUBLIC_parameters_kdf_scheme.set(inPublic, (short) 0x0010);

        var inSensitive = MemorySegment.allocateNative(TPM2B_SENSITIVE_CREATE, allocator);
        var outsideInfo = MemorySegment.allocateNative(TPM2B_DIGEST, allocator);
        var creationPCR = MemorySegment.allocateNative(TPML_PCR_SELECTION, allocator);

        var objectHandle = allocator.allocate(JAVA_INT, 0);
        int rc = (int) invoke(
                esysCreatePrimary, esysCtx.target(), ESYS_TR_RH_OWNER,
                ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                inSensitive, inPublic, outsideInfo, creationPCR, objectHandle,
                NULL, NULL, NULL, NULL);
        if (rc != 0) {
            throw new SecurityException("esysCreatePrimary failed: " + tss2RcDecode(rc));
        }
        var primary = objectHandle.get(JAVA_INT, 0);
        return new Ref<>(primary, () -> esysFlushContext(esysCtx, primary));
    }

    static void esysFlushContext(Ref<MemoryAddress> esysCtx, int flushHandle) {
        int rc = (int) invoke(esysFlushContext, esysCtx.target(), flushHandle);
        if (rc != 0) {
            throw new SecurityException("esysFlushContext failed: " + tss2RcDecode(rc));
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

    private static MemorySegment cast(MemoryAddress address, MemoryLayout layout, MemorySession allocator) {
        return MemorySegment.ofAddress(address, layout.byteSize(), allocator);
    }

    record Ref<T> (T target, Runnable destructor) implements AutoCloseable {
        @Override
        public void close() {
            destructor.run();
        }
    }

    public static void main(String[] args) throws Exception {
        var l = new ArrayList<String>();
        for (Field f : LibTss2.class.getDeclaredFields()) {
            if ((f.getModifiers() & Modifier.STATIC) != 0 && f.getType().equals(MemoryLayout.class)) {
                f.setAccessible(true);
                MemoryLayout m = (MemoryLayout) f.get(null);
                l.add(f.getName() + ": " + m.byteSize());
                //l.add("printf(\"" + f.getName() + ": %lu\\n\", sizeof(" + f.getName() + "));");
            }
        }
        Collections.sort(l);
        for (String s : l) {
            System.out.println(s);
        }

        try (MemorySession allocator = MemorySession.openConfined()) {
            var pub = MemorySegment.allocateNative(TPM2B_PUBLIC, allocator);
            TPM2B_PUBLIC_publicArea_type.set(pub, (short) 0x0023);
            TPM2B_PUBLIC_publicArea_nameAlg.set(pub, (short) 0x000B);
            TPM2B_PUBLIC_publicArea_objectAttributes.set(pub, 0x00030472);
            TPM2B_PUBLIC_authPolicy_size.set(pub, (short) 0);
            TPM2B_PUBLIC_parameters_algorithm.set(pub, (short) 0x0006);
            TPM2B_PUBLIC_parameters_mode.set(pub, (short) 0x0043);
            TPM2B_PUBLIC_parameters_keyBits.set(pub, (short) 128);
            TPM2B_PUBLIC_parameters_scheme.set(pub, (short) 0x0010);
            TPM2B_PUBLIC_parameters_curveID.set(pub, (short) 0x0003);
            TPM2B_PUBLIC_parameters_kdf_scheme.set(pub, (short) 0x0010);

            var bb = pub.asByteBuffer();
            var bytes = new byte[bb.remaining()];
            bb.get(bytes);
            System.out.println(HexFormat.of().formatHex(bytes));
            System.out.println("0000000023000b007204030000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000600800043001000000000000300100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
        }

    }
}
