package com.github.alaisi.tpm;

import com.github.alaisi.tpm.internal.TpmRandom;

import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;

public class TpmProvider extends Provider {

    protected TpmProvider() {
        super("TPM", "0.0.1", "TPM provider");
        put("SecureRandom.TPM", TpmRandom.class.getName());
    }

    public static void main(String[] args) throws Throwable {
        Provider p = new TpmProvider();
        Security.insertProviderAt(p, 0);

        var r = SecureRandom.getInstance("TPM");
        System.out.printf("random: %d\n", r.nextInt());
    }
}
