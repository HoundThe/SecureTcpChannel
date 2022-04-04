from tpm2_pytss import *
import hashlib


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


def get_signed_pcr(ectx):
    """
    Get the PCR values and their signature using ECDSA and SHA256
    """
    rand_nonce = bytes(ectx.get_random(20))
    key = create_primary(ectx)
    key_handle = key[0]
    scheme = TPMT_SIG_SCHEME(scheme=TPM2_ALG.ECDSA)
    scheme.details.any.hashAlg = TPM2_ALG.SHA256
    quote, signature = ectx.quote(key_handle, "sha256:0,1,2,3,4,5,6,7", rand_nonce, scheme)
    m = hashlib.sha256()
    m.update(bytes(quote))
    quote_digest = m.digest()
    verified = ectx.verify_signature(key_handle, quote_digest, signature)
    if type(verified) != TPMT_TK_VERIFIED:
        return None
    ectx.flush_context(key_handle)
    return quote, signature


tcti = TCTILdr("mssim", f"port=2321")
ectx = ESAPI(tcti)
ectx.startup(TPM2_SU.CLEAR)
q, s = get_signed_pcr(ectx)
ectx.shutdown(TPM2_SU.CLEAR)
