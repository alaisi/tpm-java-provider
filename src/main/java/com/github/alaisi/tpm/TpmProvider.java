package com.github.alaisi.tpm;

import com.github.alaisi.tpm.internal.TpmRsaKeyPairGenerator;
import com.github.alaisi.tpm.internal.TpmSecureRandom;
import com.github.alaisi.tpm.internal.TpmSignature;

import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.HexFormat;

public class TpmProvider extends Provider {

    protected TpmProvider() {
        super("TPM", "0.0.1", "TPM provider");
        put("SecureRandom.TPM", TpmSecureRandom.class.getName());
        put("KeyPairGenerator.RSA", TpmRsaKeyPairGenerator.class.getName());
        put("Signature.Sha256withRSA", TpmSignature.class.getName());
    }

    public static void main(String[] args) throws Throwable {
        Provider p = new TpmProvider();
        Security.insertProviderAt(p, 1);

        var r = SecureRandom.getInstance("TPM");
        r.setSeed(new byte[165]);
        var b = new byte[2048];
        r.nextBytes(b);
        System.out.printf("random: %s (java)\n", HexFormat.of().formatHex(b));

        var kpGen = KeyPairGenerator.getInstance("RSA", p);
        kpGen.initialize(2048);
        var kp = kpGen.generateKeyPair();
        System.out.printf("pub=%s\npriv=%s\n", kp.getPublic(), kp.getPrivate());
        var pub = (RSAPublicKey) kp.getPublic();

        var kf = KeyFactory.getInstance("RSA");
        var sunPub = kf.generatePublic(new RSAPublicKeySpec(pub.getModulus(), pub.getPublicExponent()));
        System.out.println(sunPub);

        var sig = Signature.getInstance("Sha256withRSA", p);
        sig.initSign(kp.getPrivate());
        sig.update(new byte[10]);
        var signed = sig.sign();
    }
}
