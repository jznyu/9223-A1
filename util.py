from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature


# extracts and returns the public key from a certificate provided as PEM bytes or text
def extract_public_key(certificate_pem: bytes | str) -> bytes:
    # normalize to bytes
    certificate_bytes = (
        certificate_pem.encode("utf-8")
        if isinstance(certificate_pem, str)
        else certificate_pem
    )

    # load the certificate from PEM bytes
    certificate = x509.load_pem_x509_certificate(certificate_bytes)

    # extract and return the public key (Fulcio certs use ECDSA P-256)
    public_key = certificate.public_key()

    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    # save the public key to a PEM file
    return pem_public_key


def verify_artifact_signature(
    signature: bytes, public_key_pem: bytes, artifact_filename: str
) -> bool:
    public_key = load_pem_public_key(public_key_pem)

    with open(artifact_filename, "rb") as data_file:
        data = data_file.read()

    # verify the signature
    try:
        public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        print("Signature verified successfully")
    except InvalidSignature as e:
        print(f"Invalid signature: {e}")
        return False
    except Exception as e:
        print(f"Error verifying artifact signature: {e}")
        return False

    return True
