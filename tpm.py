from tpm2_pytss import *
import cryptography.hazmat.primitives.asymmetric.ec as ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
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


def get_signed_pcr(ectx, random_nonce):
    """
    Get the PCR values and their signature using ECDSA and SHA256
    """
    key = create_primary(ectx)
    key_handle = key[0]
    scheme = TPMT_SIG_SCHEME(scheme=TPM2_ALG.ECDSA)
    scheme.details.any.hashAlg = TPM2_ALG.SHA256
    quote, signature = ectx.quote(key_handle, "sha256:0,1,2,3,4,5,6,7", random_nonce, scheme)
    quote_data = bytes(quote)
    m = hashlib.sha256()
    m.update(quote_data)
    quote_digest = m.digest()
    verified = ectx.verify_signature(key_handle, quote_digest, signature)
    if type(verified) != TPMT_TK_VERIFIED:
        return None

    pub_x = bytes(key[1].publicArea.unique.ecc.x)
    pub_y = bytes(key[1].publicArea.unique.ecc.y)
    sig_r = bytes(signature.signature.ecdsa.signatureR)
    sig_s = bytes(signature.signature.ecdsa.signatureS)
    ectx.flush_context(key_handle)
    return pub_x, pub_y, sig_r, sig_s, quote_data


def validate_quote_data(quote_data, pub_x, pub_y, sig_r, sig_s):
    pub_nums = ec.EllipticCurvePublicNumbers(
        curve=ec.SECP256R1(), x=int.from_bytes(pub_x, "big"), y=int.from_bytes(pub_y, "big")
    )
    pub_key = pub_nums.public_key()
    try:
        pub_key.verify(
            encode_dss_signature(r=int.from_bytes(sig_r, "big"), s=int.from_bytes(sig_s, "big")),
            quote_data,
            ec.ECDSA(hashes.SHA256()),
        )
    except InvalidSignature as sig_e:
        print(sig_e)
        return False
    return True


def init_tpm():
    tcti = TCTILdr("mssim", f"port=2321")
    ectx = ESAPI(tcti)
    ectx.startup(TPM2_SU.CLEAR)
    return ectx


def shutdown_tpm(ectx):
    ectx.shutdown(TPM2_SU.CLEAR)
