package com.github.alaisi.tpm.internal;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.math.BigInteger;
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
    private static final MethodHandle esysCreate;
    private static final MethodHandle esysLoad;

    private static final int ESYS_TR_NONE = 0xfff;
    private static final int ESYS_TR_RH_OWNER = 0x101;
    private static final int ESYS_TR_PASSWORD = 0x0ff;
    private static final short TPM2_ALG_ECC = 0x0023;
    private static final short TPM2_ALG_SHA256 = 0x000b;
    private static final short TPM2_ALG_AES = 0x0006;
    private static final short TPM2_ALG_CFB = 0x0043;
    private static final short TPM2_ALG_NULL = 0x0010;
    private static final short TPM2_ECC_NIST_P256 = 0x0003;
    private static final short TPM2_ALG_RSA = 0x0001;

    static {
        var linker = Linker.nativeLinker();

        var libTss2Esys = SymbolLookup.libraryLookup("libtss2-esys.so.0", openImplicit());
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
        esysCreate = linker.downcallHandle(
                libTss2Esys.lookup("Esys_Create").orElseThrow(),
                FunctionDescriptor.of(
                        JAVA_INT, ADDRESS, JAVA_INT, JAVA_INT, JAVA_INT, JAVA_INT,
                        ADDRESS, ADDRESS, ADDRESS, ADDRESS, ADDRESS, ADDRESS, ADDRESS, ADDRESS, ADDRESS));
        esysLoad = linker.downcallHandle(
                libTss2Esys.lookup("Esys_Load").orElseThrow(),
                FunctionDescriptor.of(
                        JAVA_INT, ADDRESS, JAVA_INT, JAVA_INT, JAVA_INT, JAVA_INT,
                        ADDRESS, ADDRESS, ADDRESS));
        esysFree = linker.downcallHandle(
                libTss2Esys.lookup("Esys_Free").orElseThrow(),
                FunctionDescriptor.ofVoid(ADDRESS));

        var libTss2Rc = SymbolLookup.libraryLookup("libtss2-rc.so.0", openImplicit());
        tss2RcDecode = linker.downcallHandle(
                libTss2Rc.lookup("Tss2_RC_Decode").orElseThrow(),
                FunctionDescriptor.of(ADDRESS, JAVA_INT));
    }

    static Ref<MemoryAddress> esysInitialize(MemorySession allocator) {
        var esysCtxPtr = MemorySegment.allocateNative(ADDRESS, allocator);
        var rc = (int) invoke(esysInitialize, esysCtxPtr, NULL, NULL);
        if (rc != 0) {
            throw new SecurityException("esysInitialize failed: " + tss2RcDecode(rc));
        }
        return new Ref<>(
                esysCtxPtr.get(ADDRESS, 0),
                () -> invoke(esysFinalize, esysCtxPtr));
    }

    static byte[] esysGetRandom(MemorySession allocator, Ref<MemoryAddress> esysCtx, int count) {
        var randomPtr = MemorySegment.allocateNative(ADDRESS, allocator);
        var rc = (int) invoke(esysGetRandom, esysCtx.target(),
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
            var rc = (int) invoke(esysStirRandom, esysCtx.target(), ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, stir);
            if (rc != 0) {
                throw new SecurityException("esysStirRandom failed: " + tss2RcDecode(rc));
            }
        }
    }

    static Ref<Integer> esysCreatePrimary(MemorySession allocator, Ref<MemoryAddress> esysCtx) {
        var inPublic = MemorySegment.allocateNative(TPM2B_PUBLIC, allocator);
        TPM2B_PUBLIC_type.set(inPublic, TPM2_ALG_ECC);
        TPM2B_PUBLIC_publicArea_nameAlg.set(inPublic, TPM2_ALG_SHA256);
        TPM2B_PUBLIC_objectAttributes.set(inPublic, 0x00030472);
        TPM2B_PUBLIC_parameters_eccDetail_symmetric_algorithm.set(inPublic, TPM2_ALG_AES);
        TPM2B_PUBLIC_parameters_eccDetail_symmetric_mode.set(inPublic, TPM2_ALG_CFB);
        TPM2B_PUBLIC_parameters_eccDetail_symmetric_keyBits.set(inPublic, (short) 128);
        TPM2B_PUBLIC_parameters_eccDetail_scheme_scheme.set(inPublic, TPM2_ALG_NULL);
        TPM2B_PUBLIC_parameters_eccDetail_curveID.set(inPublic, TPM2_ECC_NIST_P256);
        TPM2B_PUBLIC_parameters_eccDetail_kdf_scheme.set(inPublic, TPM2_ALG_NULL);

        var inSensitive = MemorySegment.allocateNative(TPM2B_SENSITIVE_CREATE, allocator);
        var outsideInfo = MemorySegment.allocateNative(TPM2B_DIGEST, allocator);
        var creationPCR = MemorySegment.allocateNative(TPML_PCR_SELECTION, allocator);

        var objectHandle = allocator.allocate(JAVA_INT, 0);
        var rc = (int) invoke(
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

    static Tss2RsaKey esysCreateRsa(MemorySession allocator,
                                    Ref<MemoryAddress> esysCtx,
                                    int primaryCtx,
                                    short keyBits) {
        var inPublic = MemorySegment.allocateNative(TPM2B_PUBLIC, allocator);
        TPM2B_PUBLIC_type.set(inPublic, TPM2_ALG_RSA);
        TPM2B_PUBLIC_publicArea_nameAlg.set(inPublic, TPM2_ALG_SHA256);
        TPM2B_PUBLIC_objectAttributes.set(inPublic, 0x060472);
        TPM2B_PUBLIC_parameters_rsaDetail_symmetric_algorithm.set(inPublic, TPM2_ALG_NULL);
        TPM2B_PUBLIC_parameters_rsaDetail_scheme_scheme.set(inPublic, TPM2_ALG_NULL);
        TPM2B_PUBLIC_parameters_rsaDetail_keyBits.set(inPublic, keyBits);

        var inSensitive = MemorySegment.allocateNative(TPM2B_SENSITIVE_CREATE, allocator);
        var outsideInfo = MemorySegment.allocateNative(TPM2B_DIGEST, allocator);
        var creationPCR = MemorySegment.allocateNative(TPML_PCR_SELECTION, allocator);

        var keyPrivatePtr = MemorySegment.allocateNative(ADDRESS, allocator);
        var keyPublicPtr = MemorySegment.allocateNative(ADDRESS, allocator);
        var rc = (int) invoke(
                esysCreate, esysCtx.target(), primaryCtx,
                ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                inSensitive, inPublic, outsideInfo, creationPCR,
                keyPrivatePtr, keyPublicPtr, NULL, NULL, NULL);
        if (rc != 0) {
            throw new SecurityException("esysCreatePrimary failed: " + tss2RcDecode(rc));
        }
        try (var privateRef = asRef(keyPrivatePtr.get(ADDRESS, 0));
             var publicRef = asRef(keyPublicPtr.get(ADDRESS, 0))) {
            var keyPublic = cast(publicRef.target(), TPM2B_PUBLIC, allocator);
            var exponent = (int) TPM2B_PUBLIC_parameters_rsaDetail_exponent.get(keyPublic);
            var modulus = copyBytes(
                    TPM2B_PUBLIC_parameters_rsaDetail_size,
                    TPM2B_PUBLIC_parameters_rsaDetail_buffer,
                    keyPublic);
            var privateBuffer = copyBytes(
                    TPM2B_PRIVATE_size,
                    TPM2B_PRIVATE_buffer,
                    cast(privateRef.target(), TPM2B_PRIVATE, allocator));
            try (var loaded = esysLoad(
                    allocator, esysCtx, primaryCtx,
                    privateRef.target(), publicRef.target())) {
                System.out.println("Loaded handle " + loaded.target());
            }
            return new Tss2RsaKey(
                    BigInteger.valueOf(exponent == 0 ? 65537 : exponent),
                    new BigInteger(1, modulus),
                    privateBuffer);
        }
    }

    static Ref<Integer> esysLoad(MemorySession allocator,
                                 Ref<MemoryAddress> esysCtx,
                                 int primaryCtx,
                                 MemoryAddress inPrivate,
                                 MemoryAddress inPublic) {
        var handlePtr = MemorySegment.allocateNative(ADDRESS, allocator);
        var rc = (int) invoke(
                esysLoad,
                esysCtx.target(), primaryCtx,
                ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                inPrivate,  inPublic, handlePtr);
        if (rc != 0) {
            throw new SecurityException("esysLoad failed: " + tss2RcDecode(rc));
        }
        var handle = handlePtr.get(JAVA_INT, 0);
        return new Ref<>(handle, () -> esysFlushContext(esysCtx, handle));
    }

    static void esysFlushContext(Ref<MemoryAddress> esysCtx, int flushHandle) {
        var rc = (int) invoke(esysFlushContext, esysCtx.target(), flushHandle);
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

    private static byte[] copyBytes(VarHandle sizeHandle, VarHandle bufHandle, MemorySegment struct) {
        var bytes = new byte[(int) sizeHandle.get(struct)];
        for (var i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) bufHandle.get(struct, i);
        }
        return bytes;
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
    record Tss2RsaKey(BigInteger publicExponent, BigInteger modulus, byte[] privateBuffer) {}

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
            TPM2B_PUBLIC_type.set(pub, TPM2_ALG_ECC);
            TPM2B_PUBLIC_publicArea_nameAlg.set(pub, TPM2_ALG_SHA256);
            TPM2B_PUBLIC_objectAttributes.set(pub, 0x00030472);
            TPM2B_PUBLIC_parameters_eccDetail_symmetric_algorithm.set(pub, TPM2_ALG_AES);
            TPM2B_PUBLIC_parameters_eccDetail_symmetric_mode.set(pub, TPM2_ALG_CFB);
            TPM2B_PUBLIC_parameters_eccDetail_symmetric_keyBits.set(pub, (short) 128);
            TPM2B_PUBLIC_parameters_eccDetail_scheme_scheme.set(pub, TPM2_ALG_NULL);
            TPM2B_PUBLIC_parameters_eccDetail_curveID.set(pub, TPM2_ECC_NIST_P256);
            TPM2B_PUBLIC_parameters_eccDetail_kdf_scheme.set(pub, TPM2_ALG_NULL);

            var bb = pub.asByteBuffer();
            var bytes = new byte[bb.remaining()];
            bb.get(bytes);
            System.out.println(HexFormat.of().formatHex(bytes));
            System.out.println("0000000023000b007204030000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000600800043001000000000000300100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
        }

    }
}
