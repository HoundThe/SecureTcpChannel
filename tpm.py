from tpm2_pytss import *


def create_primary(ectx):
    in_sensitive = TPM2B_SENSITIVE_CREATE()
    in_public = TPM2B_PUBLIC()
    outside_info = TPM2B_DATA()
    creation_pcr = TPML_PCR_SELECTION()

    in_public.publicArea.type = TPM2_ALG.ECC
    in_public.publicArea.nameAlg = TPM2_ALG.SHA1
    in_public.publicArea.objectAttributes = (
            TPMA_OBJECT.USERWITHAUTH
            | TPMA_OBJECT.SIGN_ENCRYPT
            | TPMA_OBJECT.RESTRICTED
            | TPMA_OBJECT.FIXEDTPM
            | TPMA_OBJECT.FIXEDPARENT
            | TPMA_OBJECT.SENSITIVEDATAORIGIN
    )

    in_public.publicArea.parameters.eccDetail.scheme.scheme = TPM2_ALG.ECDSA
    in_public.publicArea.parameters.eccDetail.scheme.details.ecdsa.hashAlg = (
        TPM2_ALG.SHA256
    )
    in_public.publicArea.parameters.eccDetail.symmetric.algorithm = TPM2_ALG.NULL
    in_public.publicArea.parameters.eccDetail.kdf.scheme = TPM2_ALG.NULL
    in_public.publicArea.parameters.eccDetail.curveID = TPM2_ECC.NIST_P256

    return ectx.create_primary(
        in_sensitive, in_public, ESYS_TR.OWNER, outside_info, creation_pcr,
    )
    # TODO Make the key persistent (out of memory issues in this function)


def sign_pcr(ectx):
    key = create_primary(ectx)
    key_handle = key[0]
    quote, signature = ectx.quote(
        key_handle, "sha1:0,1,2,3,4,5,6,7", TPM2B_DATA(b"123456789")
    )
    public = key[1]
    print(public.publicArea.unique.ecc.x)
    print(public.publicArea.unique.ecc.y)
    print(signature.signature.ecdsa.signatureR)
    print(signature.signature.ecdsa.signatureS)
    # TODO Verify TPM signature


tcti = TCTILdr("mssim", f"port=2321")
ectx = ESAPI(tcti)
ectx.startup(TPM2_SU.CLEAR)
sign_pcr(ectx)
