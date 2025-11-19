"""Tests for util.py functionality."""

import tempfile
from unittest.mock import MagicMock, patch

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

from util import extract_public_key, verify_artifact_signature


# Sample EC private key and certificate for testing
SAMPLE_EC_PRIVATE_KEY_PEM = b"""-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIIGLqHgFdDr3TfqXxJ2bqhLfKFABVrEPr8dPxJL2bXDYoAoGCCqGSM49
AwEHoUQDQgAE8V/VHvxHNm7DgwYJ+1p9R9DwLm4rP2cQpUmC4JCbQmNBp4WjXgC6
qHwB8OYD5rQqN0PvB3FXmXhCLPgzwXcLCA==
-----END EC PRIVATE KEY-----"""


def generate_test_certificate() -> bytes:
    """Generate a test certificate with EC key for testing."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.x509.oid import NameOID

    # Generate a private key
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

    # Create a self-signed certificate
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
            x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com"),
        ]
    )

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
        .sign(private_key, hashes.SHA256(), default_backend())
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    return cert_pem


class TestExtractPublicKey:
    """Test extract_public_key function."""

    def test_extract_public_key_from_bytes(self) -> None:
        """Test extracting public key from certificate bytes."""
        cert_pem = generate_test_certificate()
        public_key_pem = extract_public_key(cert_pem)

        assert public_key_pem is not None
        assert isinstance(public_key_pem, bytes)
        assert b"BEGIN PUBLIC KEY" in public_key_pem
        assert b"END PUBLIC KEY" in public_key_pem

    def test_extract_public_key_from_string(self) -> None:
        """Test extracting public key from certificate string."""
        cert_pem = generate_test_certificate()
        cert_str = cert_pem.decode("utf-8")

        public_key_pem = extract_public_key(cert_str)

        assert public_key_pem is not None
        assert isinstance(public_key_pem, bytes)
        assert b"BEGIN PUBLIC KEY" in public_key_pem

    def test_extract_public_key_invalid_certificate(self) -> None:
        """Test error handling with invalid certificate."""
        invalid_cert = b"not a valid certificate"

        with pytest.raises(Exception):  # Will raise a cryptography exception
            extract_public_key(invalid_cert)

    def test_extract_public_key_format(self) -> None:
        """Test that extracted key is in correct PEM format."""
        cert_pem = generate_test_certificate()
        public_key_pem = extract_public_key(cert_pem)

        # Should be able to load the public key
        from cryptography.hazmat.primitives.serialization import load_pem_public_key

        public_key = load_pem_public_key(public_key_pem)
        assert public_key is not None


class TestVerifyArtifactSignature:
    """Test verify_artifact_signature function."""

    def test_verify_artifact_signature_valid(self) -> None:
        """Test signature verification with valid signature."""
        # Generate test key and certificate
        from cryptography.hazmat.backends import default_backend

        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()

        # Create public key PEM
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # Create a test artifact file
        with tempfile.NamedTemporaryFile(delete=False, mode="wb") as tmp_file:
            test_data = b"This is test artifact data"
            tmp_file.write(test_data)
            tmp_path = tmp_file.name

        try:
            # Sign the data
            signature = private_key.sign(test_data, ec.ECDSA(hashes.SHA256()))

            # Verify the signature
            result = verify_artifact_signature(signature, public_key_pem, tmp_path)

            assert result is True
        finally:
            import os

            os.unlink(tmp_path)

    def test_verify_artifact_signature_invalid(self) -> None:
        """Test signature verification with invalid signature."""
        from cryptography.hazmat.backends import default_backend

        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()

        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # Create a test artifact file
        with tempfile.NamedTemporaryFile(delete=False, mode="wb") as tmp_file:
            test_data = b"This is test artifact data"
            tmp_file.write(test_data)
            tmp_path = tmp_file.name

        try:
            # Create a signature for different data
            wrong_data = b"Different data"
            signature = private_key.sign(wrong_data, ec.ECDSA(hashes.SHA256()))

            # Verify should fail
            result = verify_artifact_signature(signature, public_key_pem, tmp_path)

            assert result is False
        finally:
            import os

            os.unlink(tmp_path)

    def test_verify_artifact_signature_wrong_key_type(self) -> None:
        """Test error handling with wrong key type."""
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.backends import default_backend

        # Generate RSA key instead of EC
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        public_key = private_key.public_key()

        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # Create a test artifact file
        with tempfile.NamedTemporaryFile(delete=False, mode="wb") as tmp_file:
            tmp_file.write(b"test data")
            tmp_path = tmp_file.name

        try:
            signature = b"fake_signature"

            with pytest.raises(
                TypeError, match="Expected EllipticCurvePublicKey"
            ):
                verify_artifact_signature(signature, public_key_pem, tmp_path)
        finally:
            import os

            os.unlink(tmp_path)

    def test_verify_artifact_signature_file_not_found(self) -> None:
        """Test error handling when artifact file doesn't exist."""
        from cryptography.hazmat.backends import default_backend

        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()

        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        signature = b"fake_signature"

        with pytest.raises(FileNotFoundError):
            verify_artifact_signature(
                signature, public_key_pem, "/nonexistent/file.txt"
            )

    def test_verify_artifact_signature_empty_file(self) -> None:
        """Test signature verification with empty artifact file."""
        from cryptography.hazmat.backends import default_backend

        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()

        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # Create an empty test artifact file
        with tempfile.NamedTemporaryFile(delete=False, mode="wb") as tmp_file:
            tmp_path = tmp_file.name

        try:
            # Sign empty data
            signature = private_key.sign(b"", ec.ECDSA(hashes.SHA256()))

            result = verify_artifact_signature(signature, public_key_pem, tmp_path)

            assert result is True
        finally:
            import os

            os.unlink(tmp_path)

    def test_verify_artifact_signature_large_file(self) -> None:
        """Test signature verification with larger artifact file."""
        from cryptography.hazmat.backends import default_backend

        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()

        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # Create a larger test artifact file
        test_data = b"Large test data " * 1000  # ~16KB
        with tempfile.NamedTemporaryFile(delete=False, mode="wb") as tmp_file:
            tmp_file.write(test_data)
            tmp_path = tmp_file.name

        try:
            signature = private_key.sign(test_data, ec.ECDSA(hashes.SHA256()))

            result = verify_artifact_signature(signature, public_key_pem, tmp_path)

            assert result is True
        finally:
            import os

            os.unlink(tmp_path)

    @patch("builtins.print")
    def test_verify_artifact_signature_prints_success(
        self, mock_print: MagicMock
    ) -> None:
        """Test that successful verification prints success message."""
        from cryptography.hazmat.backends import default_backend

        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()

        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        test_data = b"test data"
        with tempfile.NamedTemporaryFile(delete=False, mode="wb") as tmp_file:
            tmp_file.write(test_data)
            tmp_path = tmp_file.name

        try:
            signature = private_key.sign(test_data, ec.ECDSA(hashes.SHA256()))
            verify_artifact_signature(signature, public_key_pem, tmp_path)

            mock_print.assert_called_with("Signature verified successfully")
        finally:
            import os

            os.unlink(tmp_path)

    @patch("builtins.print")
    def test_verify_artifact_signature_prints_failure(
        self, mock_print: MagicMock
    ) -> None:
        """Test that failed verification prints failure message."""
        from cryptography.hazmat.backends import default_backend

        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()

        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        test_data = b"test data"
        with tempfile.NamedTemporaryFile(delete=False, mode="wb") as tmp_file:
            tmp_file.write(test_data)
            tmp_path = tmp_file.name

        try:
            # Create signature for different data
            signature = private_key.sign(b"different data", ec.ECDSA(hashes.SHA256()))
            verify_artifact_signature(signature, public_key_pem, tmp_path)

            mock_print.assert_called_with(
                "Signature verification failed: signature is invalid or artifact is not authentic."
            )
        finally:
            import os

            os.unlink(tmp_path)

