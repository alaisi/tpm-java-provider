package com.github.alaisi.tpm.internal;

import java.security.Key;

abstract class TpmKey implements Key {

    @Override
    public String getFormat() {
        return "TPM";
    }

    @Override
    public byte[] getEncoded() {
        throw new UnsupportedOperationException();
    }
}
