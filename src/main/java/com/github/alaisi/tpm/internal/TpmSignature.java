package com.github.alaisi.tpm.internal;

import com.github.alaisi.tpm.internal.TpmKey.TpmRsaPrivateKey;

import java.lang.foreign.MemorySession;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HexFormat;

public final class TpmSignature extends SignatureSpi {

    private MessageDigest digest;
    private TpmRsaPrivateKey tpmKey;

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        if (!(privateKey instanceof TpmKey)) {
            throw new InvalidKeyException("TPM key required");
        }
        try {
            this.digest = MessageDigest.getInstance("SHA-256");
            this.tpmKey = (TpmRsaPrivateKey) privateKey;
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) {
        digest.update(b, off, len);
    }

    @Override
    protected void engineUpdate(byte b) {
        digest.update(b);
    }

    @Override
    protected byte[] engineSign() {
        try (var allocator = MemorySession.openConfined()) {
            var priv = LibTss2.tss2PrivateUnmarshall(allocator, tpmKey.getMarshalledPrivate());
            var pub = LibTss2.tss2PublicUnmarshall(allocator, tpmKey.getMarshalledPublic());
            try (var esysCtx = LibTss2.esysInitialize(allocator);
                 var primaryCtx = LibTss2.esysCreatePrimary(allocator, esysCtx);
                 var keyCtx = LibTss2.esysLoad(allocator, esysCtx, primaryCtx.target(), priv, pub)) {
                var signature = LibTss2.esysSign(allocator, esysCtx, keyCtx.target(), digest.digest());
                System.out.println("sig = " + HexFormat.of().formatHex(signature));
                return signature;
             }
        }
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) {
        throw new UnsupportedOperationException();
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) {
        throw new UnsupportedOperationException();
    }

    @Override
    protected void engineSetParameter(AlgorithmParameterSpec params) {
        throw new UnsupportedOperationException();
    }
    @Override
    protected AlgorithmParameters engineGetParameters() {
        throw new UnsupportedOperationException();
    }

    @Override
    @Deprecated
    protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
        throw new UnsupportedOperationException();
    }
    @Override
    @Deprecated
    protected Object engineGetParameter(String param) throws InvalidParameterException {
        throw new UnsupportedOperationException();
    }
}
