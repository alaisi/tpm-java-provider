package com.github.alaisi.tpm;

import com.github.alaisi.tpm.internal.TpmRsaKeyPairGenerator;
import com.github.alaisi.tpm.internal.TpmSecureRandom;

import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.HexFormat;

public class TpmProvider extends Provider {

    protected TpmProvider() {
        super("TPM", "0.0.1", "TPM provider");
        put("SecureRandom.TPM", TpmSecureRandom.class.getName());
        put("KeyPairGenerator.RSA", TpmRsaKeyPairGenerator.class.getName());
    }

    public static void main(String[] args) throws Throwable {
        Provider p = new TpmProvider();
        Security.insertProviderAt(p, 0);

        var r = SecureRandom.getInstance("TPM");
        //r.setSeed(new byte[165]);
        //var b = new byte[2048];
        //r.nextBytes(b);
        //System.out.printf("random: %s (java)\n", HexFormat.of().formatHex(b));

        var kpGen = KeyPairGenerator.getInstance("RSA", p);
        kpGen.initialize(2048);
        var kp = kpGen.generateKeyPair();
        //System.out.printf("%s: %s\n", kp.getPrivate().getClass(), kp.getPrivate());

    }
}
