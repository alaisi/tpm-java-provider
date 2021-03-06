package com.github.alaisi.tpm.internal;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.math.BigInteger;

import static com.github.alaisi.tpm.internal.LibTss2Types.*;
import static java.lang.foreign.MemoryAddress.NULL;
import static java.lang.foreign.ValueLayout.*;

enum LibTss2 { ;

    private static final MethodHandle Esys_Initialize;
    private static final MethodHandle Esys_Finalize;
    private static final MethodHandle Esys_GetRandom;
    private static final MethodHandle Esys_StirRandom;
    private static final MethodHandle Esys_Free;
    private static final MethodHandle Tss2_RC_Decode;
    private static final MethodHandle Esys_CreatePrimary;
    private static final MethodHandle Esys_FlushContext;
    private static final MethodHandle Esys_Create;
    private static final MethodHandle Esys_Load;
    private static final MethodHandle Esys_Sign;
    private static final MethodHandle Tss2_MU_TPM2B_PRIVATE_Marshal;
    private static final MethodHandle Tss2_MU_TPM2B_PRIVATE_Unmarshal;
    private static final MethodHandle Tss2_MU_TPM2B_PUBLIC_Marshal;
    private static final MethodHandle Tss2_MU_TPM2B_PUBLIC_Unmarshal;

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
    private static final short TPM2_ALG_RSASSA = 0x0014;
    private static final short TPM2_ST_HASHCHECK = (short) 0x8024;
    private static final int TPM2_RH_NULL = 0x40000007;

    static {
        var linker = Linker.nativeLinker();
        var allocator = MemorySession.openImplicit();

        var libTss2Esys = SymbolLookup.libraryLookup("libtss2-esys.so.0", allocator);
        Esys_Initialize = linker.downcallHandle(
                libTss2Esys.lookup("Esys_Initialize").orElseThrow(),
                FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS, ADDRESS));
        Esys_Finalize = linker.downcallHandle(
                libTss2Esys.lookup("Esys_Finalize").orElseThrow(),
                FunctionDescriptor.ofVoid(ADDRESS));
        Esys_GetRandom = linker.downcallHandle(
                libTss2Esys.lookup("Esys_GetRandom").orElseThrow(),
                FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_INT, JAVA_INT, JAVA_INT, JAVA_SHORT, ADDRESS));
        Esys_StirRandom = linker.downcallHandle(
                libTss2Esys.lookup("Esys_StirRandom").orElseThrow(),
                FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_INT, JAVA_INT, JAVA_INT, ADDRESS));
        Esys_CreatePrimary = linker.downcallHandle(
                libTss2Esys.lookup("Esys_CreatePrimary").orElseThrow(),
                FunctionDescriptor.of(
                        JAVA_INT, ADDRESS, JAVA_INT, JAVA_INT, JAVA_INT, JAVA_INT,
                        ADDRESS, ADDRESS, ADDRESS, ADDRESS, ADDRESS, ADDRESS, ADDRESS, ADDRESS, ADDRESS));
        Esys_FlushContext = linker.downcallHandle(
                libTss2Esys.lookup("Esys_FlushContext").orElseThrow(),
                FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_INT));
        Esys_Create = linker.downcallHandle(
                libTss2Esys.lookup("Esys_Create").orElseThrow(),
                FunctionDescriptor.of(
                        JAVA_INT, ADDRESS, JAVA_INT, JAVA_INT, JAVA_INT, JAVA_INT,
                        ADDRESS, ADDRESS, ADDRESS, ADDRESS, ADDRESS, ADDRESS, ADDRESS, ADDRESS, ADDRESS));
        Esys_Load = linker.downcallHandle(
                libTss2Esys.lookup("Esys_Load").orElseThrow(),
                FunctionDescriptor.of(
                        JAVA_INT, ADDRESS, JAVA_INT, JAVA_INT, JAVA_INT, JAVA_INT,
                        ADDRESS, ADDRESS, ADDRESS));
        Esys_Sign = linker.downcallHandle(
                libTss2Esys.lookup("Esys_Sign").orElseThrow(),
                FunctionDescriptor.of(
                        JAVA_INT, ADDRESS, JAVA_INT, JAVA_INT, JAVA_INT, JAVA_INT,
                        ADDRESS, ADDRESS, ADDRESS, ADDRESS));
        Esys_Free = linker.downcallHandle(
                libTss2Esys.lookup("Esys_Free").orElseThrow(),
                FunctionDescriptor.ofVoid(ADDRESS));

        var libTss2Rc = SymbolLookup.libraryLookup("libtss2-rc.so.0", allocator);
        Tss2_RC_Decode = linker.downcallHandle(
                libTss2Rc.lookup("Tss2_RC_Decode").orElseThrow(),
                FunctionDescriptor.of(ADDRESS, JAVA_INT));

        var libTss2Mu = SymbolLookup.libraryLookup("libtss2-mu.so.0", allocator);
        Tss2_MU_TPM2B_PRIVATE_Marshal = linker.downcallHandle(
                libTss2Mu.lookup("Tss2_MU_TPM2B_PRIVATE_Marshal").orElseThrow(),
                FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS, JAVA_LONG, ADDRESS));
        Tss2_MU_TPM2B_PRIVATE_Unmarshal = linker.downcallHandle(
                libTss2Mu.lookup("Tss2_MU_TPM2B_PRIVATE_Unmarshal").orElseThrow(),
                FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_LONG, ADDRESS, ADDRESS));
        Tss2_MU_TPM2B_PUBLIC_Marshal = linker.downcallHandle(
                libTss2Mu.lookup("Tss2_MU_TPM2B_PUBLIC_Marshal").orElseThrow(),
                FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS, JAVA_LONG, ADDRESS));
        Tss2_MU_TPM2B_PUBLIC_Unmarshal = linker.downcallHandle(
                libTss2Mu.lookup("Tss2_MU_TPM2B_PUBLIC_Unmarshal").orElseThrow(),
                FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_LONG, ADDRESS, ADDRESS));
    }

    static Ref<MemoryAddress> esysInitialize(MemorySession allocator) {
        var esysCtxPtr = MemorySegment.allocateNative(ADDRESS, allocator);
        var rc = (int) invoke(Esys_Initialize, esysCtxPtr, NULL, NULL);
        if (rc != 0) {
            throw new SecurityException("esysInitialize failed: " + tss2RcDecode(rc));
        }
        return new Ref<>(
                esysCtxPtr.get(ADDRESS, 0),
                () -> invoke(Esys_Finalize, esysCtxPtr));
    }

    static byte[] esysGetRandom(MemorySession allocator, Ref<MemoryAddress> esysCtx, int count) {
        var randomPtr = MemorySegment.allocateNative(ADDRESS, allocator);
        var rc = (int) invoke(Esys_GetRandom, esysCtx.target(),
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
            var rc = (int) invoke(Esys_StirRandom, esysCtx.target(), ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, stir);
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
                Esys_CreatePrimary, esysCtx.target(), ESYS_TR_RH_OWNER,
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
                Esys_Create, esysCtx.target(), primaryCtx,
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
            var modulus = readBytes(
                    TPM2B_PUBLIC_parameters_rsaDetail_size,
                    TPM2B_PUBLIC_parameters_rsaDetail_buffer,
                    keyPublic);
            var marshalledPrivate = tss2PrivateMarshall(allocator, privateRef.target());
            var marshalledPublic = tss2PublicMarshall(allocator, publicRef.target());
            return new Tss2RsaKey(
                    BigInteger.valueOf(exponent == 0 ? 65537 : exponent),
                    new BigInteger(1, modulus),
                    marshalledPrivate,
                    marshalledPublic);
        }
    }

    static byte[] tss2PrivateMarshall(MemorySession allocator, MemoryAddress tpm2bPrivate) {
        var bufLen = 2048L;
        var buf = allocator.allocateArray(JAVA_BYTE, bufLen);
        var outLen = allocator.allocate(ADDRESS);
        var rc = (int) invoke(Tss2_MU_TPM2B_PRIVATE_Marshal, tpm2bPrivate, buf, bufLen, outLen);
        if (rc != 0) {
            throw new SecurityException("Tss2_MU_TPM2B_PRIVATE_Marshal failed: " + tss2RcDecode(rc));
        }
        var marshalled = new byte[(int) outLen.get(JAVA_LONG, 0)];
        for (var i = 0; i < marshalled.length; i++) {
            marshalled[i] = buf.get(JAVA_BYTE, i);
        }
        return marshalled;
    }

    static MemoryAddress tss2PrivateUnmarshall(MemorySession allocator, byte[] marshalled) {
        var buf = allocator.allocateArray(JAVA_BYTE, marshalled.length);
        for (var i = 0; i < marshalled.length; i++) {
            buf.set(JAVA_BYTE, i, marshalled[i]);
        }
        var offset = allocator.allocate(ADDRESS);
        var tpm2bPrivate = MemorySegment.allocateNative(TPM2B_PRIVATE, allocator);
        var rc = (int) invoke(Tss2_MU_TPM2B_PRIVATE_Unmarshal, buf, (long) marshalled.length, offset, tpm2bPrivate);
        if (rc != 0) {
            throw new SecurityException("Tss2_MU_TPM2B_PRIVATE_Unmarshal failed: " + tss2RcDecode(rc));
        }
        return tpm2bPrivate.address();
    }

    static byte[] tss2PublicMarshall(MemorySession allocator, MemoryAddress tpm2bPublic) {
        var bufLen = 2048L;
        var buf = allocator.allocateArray(JAVA_BYTE, bufLen);
        var outLen = allocator.allocate(ADDRESS);
        var rc = (int) invoke(Tss2_MU_TPM2B_PUBLIC_Marshal, tpm2bPublic, buf, bufLen, outLen);
        if (rc != 0) {
            throw new SecurityException("Tss2_MU_TPM2B_PUBLIC_Marshal failed: " + tss2RcDecode(rc));
        }
        var marshalled = new byte[(int) outLen.get(JAVA_LONG, 0)];
        for (var i = 0; i < marshalled.length; i++) {
            marshalled[i] = buf.get(JAVA_BYTE, i);
        }
        return marshalled;
    }

    static MemoryAddress tss2PublicUnmarshall(MemorySession allocator, byte[] marshalled) {
        var buf = allocator.allocateArray(JAVA_BYTE, marshalled.length);
        for (var i = 0; i < marshalled.length; i++) {
            buf.set(JAVA_BYTE, i, marshalled[i]);
        }
        var offset = allocator.allocate(ADDRESS);
        var tpm2bPrivate = MemorySegment.allocateNative(TPM2B_PUBLIC, allocator);
        var rc = (int) invoke(Tss2_MU_TPM2B_PUBLIC_Unmarshal, buf, (long) marshalled.length, offset, tpm2bPrivate);
        if (rc != 0) {
            throw new SecurityException("Tss2_MU_TPM2B_PUBLIC_Unmarshal failed: " + tss2RcDecode(rc));
        }
        return tpm2bPrivate.address();
    }

    static Ref<Integer> esysLoad(MemorySession allocator,
                                 Ref<MemoryAddress> esysCtx,
                                 int primaryCtx,
                                 MemoryAddress inPrivate,
                                 MemoryAddress inPublic) {
        var handlePtr = MemorySegment.allocateNative(ADDRESS, allocator);
        var rc = (int) invoke(
                Esys_Load,
                esysCtx.target(), primaryCtx,
                ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                inPrivate,  inPublic, handlePtr);
        if (rc != 0) {
            throw new SecurityException("esysLoad failed: " + tss2RcDecode(rc));
        }
        var handle = handlePtr.get(JAVA_INT, 0);
        return new Ref<>(handle, () -> esysFlushContext(esysCtx, handle));
    }

    static byte[] esysSign(MemorySession allocator,
                           Ref<MemoryAddress> esysCtx,
                           int keyHandle,
                           byte[] digestBytes) {
        var scheme = MemorySegment.allocateNative(TPMT_SIG_SCHEME, allocator);
        TPMT_SIG_SCHEME_scheme.set(scheme, TPM2_ALG_RSASSA);
        TPMT_SIG_SCHEME_details_rsassa_hashAlg.set(scheme, TPM2_ALG_SHA256);

        var digest = MemorySegment.allocateNative(TPM2B_DIGEST, allocator);
        writeBytes(digestBytes, digest, TPM2B_DIGEST_size, TPM2B_DIGEST_buffer);

        var validation = MemorySegment.allocateNative(TPMT_TK_HASHCHECK, allocator);
        TPMT_TK_HASHCHECK_tag.set(validation, TPM2_ST_HASHCHECK);
        TPMT_TK_HASHCHECK_hierarchy.set(validation, TPM2_RH_NULL);
        TPMT_TK_HASHCHECK_digest_size.set(validation, (short) 0);

        var signaturePtr = MemorySegment.allocateNative(ADDRESS, allocator);
        var rc = (int) invoke(Esys_Sign, esysCtx.target(), keyHandle,
                ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                digest, scheme, validation, signaturePtr);
        if (rc != 0) {
            throw new SecurityException("Esys_Sign failed: " + tss2RcDecode(rc));
        }
        try (var signatureRef = asRef(signaturePtr.get(ADDRESS, 0))) {
            return readBytes(
                    TPMT_SIGNATURE_signature_rsassa_sig_size,
                    TPMT_SIGNATURE_signature_rsassa_sig_buffer,
                    cast(signatureRef.target(), TPMT_SIGNATURE, allocator));
        }
    }

    static void esysFlushContext(Ref<MemoryAddress> esysCtx, int flushHandle) {
        var rc = (int) invoke(Esys_FlushContext, esysCtx.target(), flushHandle);
        if (rc != 0) {
            throw new SecurityException("esysFlushContext failed: " + tss2RcDecode(rc));
        }
    }

    static void esysFree(MemoryAddress ptr) {
        invoke(Esys_Free, ptr);
    }

    static String tss2RcDecode(int rc) {
        var err = (MemoryAddress) invoke(Tss2_RC_Decode, rc);
        return err.getUtf8String(0);
    }

    private static Object invoke(MethodHandle methodHandle, Object... args) {
        try {
            return methodHandle.invokeWithArguments(args);
        } catch (Throwable t) {
            throw new RuntimeException(t);
        }
    }

    private static byte[] readBytes(VarHandle sizeHandle, VarHandle bufHandle, MemorySegment struct) {
        var bytes = new byte[(int) sizeHandle.get(struct)];
        for (var i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) bufHandle.get(struct, i);
        }
        return bytes;
    }

    private static void writeBytes(byte[] bytes, MemorySegment struct, VarHandle sizeHandle, VarHandle bufHandle) {
        sizeHandle.set(struct, (short) bytes.length);
        for (var i = 0; i < bytes.length; i++) {
            bufHandle.set(struct, i, bytes[i]);
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

    record Tss2RsaKey(BigInteger publicExponent,
                      BigInteger modulus,
                      byte[] marshalledPrivate,
                      byte[] marshalledPublic) {}

}
