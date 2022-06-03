package com.github.alaisi.tpm.internal;

import java.lang.foreign.MemoryLayout;
import java.lang.invoke.VarHandle;

import static java.lang.foreign.MemoryLayout.PathElement.groupElement;
import static java.lang.foreign.MemoryLayout.PathElement.sequenceElement;
import static java.lang.foreign.MemoryLayout.*;
import static java.lang.foreign.ValueLayout.*;

enum LibTss2Types { ;

    // TPM2B_DIGEST

    static final MemoryLayout TPM2B_DIGEST = structLayout(
            JAVA_SHORT.withName("size"),
            sequenceLayout(64, JAVA_BYTE).withName("buffer"));

    static final VarHandle TPM2B_DIGEST_size = TPM2B_DIGEST.varHandle(
            groupElement("size"));

    static final VarHandle TPM2B_DIGEST_buffer = TPM2B_DIGEST.varHandle(
            groupElement("buffer"),
            sequenceElement());

    // TPM2B_SENSITIVE_DATA

    static final MemoryLayout TPM2B_SENSITIVE_DATA = structLayout(
            JAVA_SHORT.withName("size"),
            sequenceLayout(256, JAVA_BYTE).withName("buffer")
    );

    static final VarHandle TPM2B_SENSITIVE_DATA_size = TPM2B_SENSITIVE_DATA.varHandle(
            groupElement("size"));

    static final VarHandle TPM2B_SENSITIVE_DATA_buffer = TPM2B_SENSITIVE_DATA.varHandle(
            groupElement("buffer"),
            sequenceElement());

    // TPM2B_PUBLIC

    static final MemoryLayout TPMT_SYM_DEF_OBJECT = structLayout(
            JAVA_SHORT.withName("algorithm"),
            JAVA_SHORT.withName("keyBits"),
            JAVA_SHORT.withName("mode"));

    static final MemoryLayout TPMS_SYMCIPHER_PARMS = structLayout(
            TPMT_SYM_DEF_OBJECT.withName("sym"));

    static final MemoryLayout TPMS_SCHEME_HASH = structLayout(
            JAVA_SHORT.withName("hashAlg"));

    static final MemoryLayout TPMS_SCHEME_ECDAA = structLayout(
            JAVA_SHORT.withName("hashAlg"),
            JAVA_SHORT.withName("count"));

    static final MemoryLayout TPMU_ASYM_SCHEME = unionLayout(
            TPMS_SCHEME_HASH.withName("anySig"),
            TPMS_SCHEME_ECDAA.withName("ecdaa"));

    static final MemoryLayout TPMT_RSA_SCHEME = structLayout(
            JAVA_SHORT.withName("scheme"),
            TPMU_ASYM_SCHEME.withName("details"));

    static final MemoryLayout TPMS_RSA_PARMS = structLayout(
            TPMT_SYM_DEF_OBJECT.withName("symmetric"),
            TPMT_RSA_SCHEME.withName("scheme"),
            JAVA_SHORT.withName("keyBits"),
            paddingLayout(2*8),
            JAVA_INT.withName("exponent"));

    static final MemoryLayout TPMS_KEYEDHASH_PARMS = structLayout(
            structLayout(
                    JAVA_SHORT.withName("scheme"),
                    unionLayout(
                            TPMS_SCHEME_HASH.withName("hmac"),
                            structLayout(
                                    JAVA_SHORT.withName("hashAlg"),
                                    JAVA_SHORT.withName("kdf")
                            ).withName("exclusiveOr")
                    ).withName("details")
            ).withName("scheme"));

    static final MemoryLayout TPMT_ECC_SCHEME = structLayout(
            JAVA_SHORT.withName("scheme"),
            TPMU_ASYM_SCHEME.withName("details"));

    static final MemoryLayout TPMT_KDF_SCHEME = structLayout(
            JAVA_SHORT.withName("scheme"),
            TPMS_SCHEME_HASH.withName("details"));

    static final MemoryLayout TPMS_ECC_PARMS = structLayout(
            TPMT_SYM_DEF_OBJECT.withName("symmetric"),
            TPMT_ECC_SCHEME.withName("scheme"),
            JAVA_SHORT.withName("curveID"),
            TPMT_KDF_SCHEME.withName("kdf"));

    static final MemoryLayout TPMS_ASYM_PARMS = structLayout(
            TPMT_SYM_DEF_OBJECT.withName("symmetric"),
            TPMT_ECC_SCHEME.withName("scheme"));

    static final MemoryLayout TPMU_PUBLIC_PARMS = unionLayout(
            TPMS_KEYEDHASH_PARMS.withName("keyedHashDetail"),
            TPMS_SYMCIPHER_PARMS.withName("symDetail"),
            TPMS_RSA_PARMS.withName("rsaDetail"),
            TPMS_ECC_PARMS.withName("eccDetail"),
            TPMS_ASYM_PARMS.withName("asymDetail"));

    static final MemoryLayout TPM2B_PUBLIC_KEY_RSA = structLayout(
            JAVA_SHORT.withName("size"),
            sequenceLayout(512, JAVA_BYTE).withName("buffer"));

    static final MemoryLayout TPM2B_ECC_PARAMETER = structLayout(
            JAVA_SHORT.withName("size"),
            sequenceLayout(128, JAVA_BYTE).withName("buffer"));

    static final MemoryLayout TPMS_ECC_POINT = structLayout(
            TPM2B_ECC_PARAMETER.withName("x"),
            TPM2B_ECC_PARAMETER.withName("y")
    );

    static final MemoryLayout TPMU_PUBLIC_ID = unionLayout(
            TPM2B_DIGEST.withName("keyedHash"),
            TPM2B_DIGEST.withName("sym"),
            TPM2B_PUBLIC_KEY_RSA.withName("rsa"),
            TPMS_ECC_POINT.withName("ecc"));

    static final MemoryLayout TPMT_PUBLIC = structLayout(
            JAVA_SHORT.withName("type"),
            JAVA_SHORT.withName("nameAlg"),
            JAVA_INT.withName("objectAttributes"),
            TPM2B_DIGEST.withName("authPolicy"),
            paddingLayout(2*8),
            TPMU_PUBLIC_PARMS.withName("parameters"),
            TPMU_PUBLIC_ID.withName("unique"));

    static final MemoryLayout TPM2B_PUBLIC = structLayout(
            JAVA_SHORT.withName("size"),
            paddingLayout(2*8),
            TPMT_PUBLIC.withName("publicArea"),
            paddingLayout(2*8));

    static final VarHandle TPM2B_PUBLIC_type = TPM2B_PUBLIC.varHandle(
            groupElement("publicArea"),
            groupElement("type"));

    static final VarHandle TPM2B_PUBLIC_publicArea_nameAlg = TPM2B_PUBLIC.varHandle(
            groupElement("publicArea"),
            groupElement("nameAlg"));

    static final VarHandle TPM2B_PUBLIC_objectAttributes = TPM2B_PUBLIC.varHandle(
            groupElement("publicArea"),
            groupElement("objectAttributes"));

    static final VarHandle TPM2B_PUBLIC_authPolicy_size = TPM2B_PUBLIC.varHandle(
            groupElement("publicArea"),
            groupElement("authPolicy"),
            groupElement("size"));

    static final VarHandle TPM2B_PUBLIC_parameters_eccDetail_symmetric_keyBits = TPM2B_PUBLIC.varHandle(
            groupElement("publicArea"),
            groupElement("parameters"),
            groupElement("eccDetail"),
            groupElement("symmetric"),
            groupElement("keyBits"));

    static final VarHandle TPM2B_PUBLIC_parameters_eccDetail_symmetric_algorithm = TPM2B_PUBLIC.varHandle(
            groupElement("publicArea"),
            groupElement("parameters"),
            groupElement("eccDetail"),
            groupElement("symmetric"),
            groupElement("algorithm"));

    static final VarHandle TPM2B_PUBLIC_parameters_eccDetail_symmetric_mode = TPM2B_PUBLIC.varHandle(
            groupElement("publicArea"),
            groupElement("parameters"),
            groupElement("eccDetail"),
            groupElement("symmetric"),
            groupElement("mode"));

    static final VarHandle TPM2B_PUBLIC_parameters_eccDetail_scheme_scheme = TPM2B_PUBLIC.varHandle(
            groupElement("publicArea"),
            groupElement("parameters"),
            groupElement("eccDetail"),
            groupElement("scheme"),
            groupElement("scheme"));

    static final VarHandle TPM2B_PUBLIC_parameters_eccDetail_curveID = TPM2B_PUBLIC.varHandle(
            groupElement("publicArea"),
            groupElement("parameters"),
            groupElement("eccDetail"),
            groupElement("curveID"));

    static final VarHandle TPM2B_PUBLIC_parameters_eccDetail_kdf_scheme = TPM2B_PUBLIC.varHandle(
            groupElement("publicArea"),
            groupElement("parameters"),
            groupElement("eccDetail"),
            groupElement("kdf"),
            groupElement("scheme"));

    static final VarHandle TPM2B_PUBLIC_parameters_rsaDetail_symmetric_algorithm = TPM2B_PUBLIC.varHandle(
            groupElement("publicArea"),
            groupElement("parameters"),
            groupElement("rsaDetail"),
            groupElement("symmetric"),
            groupElement("algorithm"));

    static final VarHandle TPM2B_PUBLIC_parameters_rsaDetail_scheme_scheme = TPM2B_PUBLIC.varHandle(
            groupElement("publicArea"),
            groupElement("parameters"),
            groupElement("rsaDetail"),
            groupElement("scheme"),
            groupElement("scheme"));

    static final VarHandle TPM2B_PUBLIC_parameters_rsaDetail_keyBits = TPM2B_PUBLIC.varHandle(
            groupElement("publicArea"),
            groupElement("parameters"),
            groupElement("rsaDetail"),
            groupElement("keyBits"));

    static final VarHandle TPM2B_PUBLIC_parameters_rsaDetail_exponent = TPM2B_PUBLIC.varHandle(
            groupElement("publicArea"),
            groupElement("parameters"),
            groupElement("rsaDetail"),
            groupElement("exponent"));

    static final VarHandle TPM2B_PUBLIC_parameters_rsaDetail_size = TPM2B_PUBLIC.varHandle(
            groupElement("publicArea"),
            groupElement("unique"),
            groupElement("rsa"),
            groupElement("size"));

    static final VarHandle TPM2B_PUBLIC_parameters_rsaDetail_buffer = TPM2B_PUBLIC.varHandle(
            groupElement("publicArea"),
            groupElement("unique"),
            groupElement("rsa"),
            groupElement("buffer"),
            sequenceElement());

    // TPM2B_SENSITIVE_CREATE

    static final MemoryLayout TPMS_SENSITIVE_CREATE = structLayout(
            TPM2B_DIGEST.withName("userAuth"),
            TPM2B_SENSITIVE_DATA.withName("data"));

    static final MemoryLayout TPM2B_SENSITIVE_CREATE = structLayout(
            JAVA_SHORT.withName("size"),
            TPMS_SENSITIVE_CREATE.withName("sensitive"));

    // TPML_PCR_SELECTION

    static final MemoryLayout TPMS_PCR_SELECTION = structLayout(
            JAVA_SHORT.withName("hash"),
            JAVA_BYTE.withName("sizeofSelect"),
            sequenceLayout(32, JAVA_BYTE).withName("pcrSelect")
    );

    static final MemoryLayout TPML_PCR_SELECTION = structLayout(
            JAVA_INT.withName("count"),
            sequenceLayout(16, TPMS_PCR_SELECTION).withName("pcrSelections"));

    // TPM2B_PRIVATE

    static final MemoryLayout TPM2B_PRIVATE = structLayout(
            JAVA_SHORT.withName("size"),
            sequenceLayout(1550, JAVA_BYTE).withName("buffer"));

    static final VarHandle TPM2B_PRIVATE_size = TPM2B_PUBLIC.varHandle(
            groupElement("size"));

    static final VarHandle TPM2B_PRIVATE_buffer = TPM2B_DIGEST.varHandle(
            groupElement("buffer"),
            sequenceElement());

    // TPMT_SIG_SCHEME

    static final MemoryLayout TPMU_SIG_SCHEME = unionLayout(
            TPMS_SCHEME_HASH.withName("rsassa"));

    static final MemoryLayout TPMT_SIG_SCHEME = structLayout(
            JAVA_SHORT.withName("scheme"),
            TPMU_SIG_SCHEME.withName("details"));

    static final VarHandle TPMT_SIG_SCHEME_scheme = TPMT_SIG_SCHEME.varHandle(
            groupElement("scheme"));

    static final VarHandle TPMT_SIG_SCHEME_details_rsassa_hashAlg = TPMT_SIG_SCHEME.varHandle(
            groupElement("details"),
            groupElement("rsassa"),
            groupElement("hashAlg"));

    // TPMT_TK_HASHCHECK

    static final MemoryLayout TPMT_TK_HASHCHECK = structLayout(
            JAVA_SHORT.withName("tag"),
            paddingLayout(2*8),
            JAVA_INT.withName("hierarchy"),
            TPM2B_DIGEST.withName("digest"));

    static final VarHandle TPMT_TK_HASHCHECK_tag = TPMT_TK_HASHCHECK.varHandle(
            groupElement("tag"));

    static final VarHandle TPMT_TK_HASHCHECK_hierarchy = TPMT_TK_HASHCHECK.varHandle(
            groupElement("hierarchy"));

    static final VarHandle TPMT_TK_HASHCHECK_digest_size = TPMT_TK_HASHCHECK.varHandle(
            groupElement("digest"),
            groupElement("size"));

    // TPMT_SIGNATURE

    static final MemoryLayout TPMS_SIGNATURE_RSA = structLayout(
            JAVA_SHORT.withName("hash"),
            TPM2B_PUBLIC_KEY_RSA.withName("sig"));

    static final MemoryLayout TPMU_SIGNATURE = unionLayout(
            TPMS_SIGNATURE_RSA.withName("rsassa"));

    static final MemoryLayout TPMT_SIGNATURE = structLayout(
            JAVA_SHORT.withName("scheme"),
            TPMU_SIGNATURE.withName("signature"));

    static final VarHandle TPMT_SIGNATURE_signature_rsassa_sig_size = TPMT_SIGNATURE.varHandle(
            groupElement("signature"),
            groupElement("rsassa"),
            groupElement("sig"),
            groupElement("size"));

    static final VarHandle TPMT_SIGNATURE_signature_rsassa_sig_buffer = TPMT_SIGNATURE.varHandle(
            groupElement("signature"),
            groupElement("rsassa"),
            groupElement("sig"),
            groupElement("buffer"),
            sequenceElement());
}
