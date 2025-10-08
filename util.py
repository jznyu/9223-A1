"""Utility functions for signature verification."""

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature


# extracts and returns the public key from a certificate provided as PEM bytes or text
def extract_public_key(certificate_pem: bytes | str) -> bytes:
    """Extract the public key from a certificate provided as PEM bytes or text.

    Args:
        certificate_pem (bytes | str): The certificate in PEM format.

    Returns:
        bytes: The public key in PEM format.
    """
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
    """Verify the signature of an artifact.

    Args:
        signature (bytes): The signature of the artifact.
        public_key_pem (bytes): The public key of the artifact.
        artifact_filename (str): The filename of the artifact.

    Returns:
        bool: True if signature verification succeeds (artifact is authentic),
              False if verification fails (signature is invalid or artifact is not authentic).
    """
    public_key = load_pem_public_key(public_key_pem)
    if not isinstance(public_key, EllipticCurvePublicKey):
        raise TypeError(f"Expected EllipticCurvePublicKey, got {type(public_key)}")

    with open(artifact_filename, "rb") as data_file:
        data = data_file.read()

    # verify the signature
    try:
        public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        print("Signature verified successfully")
        return True
    except InvalidSignature:
        print(
            "Signature verification failed: signature is invalid or artifact is not authentic."
        )
        return False
