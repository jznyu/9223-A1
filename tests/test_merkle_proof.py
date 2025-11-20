"""Tests for merkle_proof.py functionality."""

import base64
import hashlib

import pytest

from rekor_verifier.merkle_proof import (
    RFC6962_LEAF_HASH_PREFIX,
    RFC6962_NODE_HASH_PREFIX,
    DefaultHasher,
    Hasher,
    RootMismatchError,
    chain_border_right,
    chain_inner,
    chain_inner_right,
    compute_leaf_hash,
    decomp_incl_proof,
    inner_proof_size,
    root_from_inclusion_proof,
    verify_consistency,
    verify_inclusion,
    verify_match,
)


class TestHasher:
    """Test Hasher class."""

    def test_hasher_creation(self) -> None:
        """Test hasher object creation."""
        hasher = Hasher(hashlib.sha256)
        assert hasher.hash_func == hashlib.sha256

    def test_hasher_new(self) -> None:
        """Test creating new hash object."""
        hasher = Hasher(hashlib.sha256)
        h = hasher.new()
        assert h is not None
        assert hasattr(h, "update")

    def test_hasher_empty_root(self) -> None:
        """Test empty root creation."""
        hasher = Hasher(hashlib.sha256)
        root = hasher.empty_root()
        assert len(root) == 32  # SHA256 produces 32 bytes

    def test_hasher_hash_leaf(self) -> None:
        """Test leaf hashing with domain separation."""
        hasher = Hasher(hashlib.sha256)
        data = b"test data"
        leaf_hash = hasher.hash_leaf(data)

        # Verify it includes the leaf prefix
        expected_hash = hashlib.sha256(
            bytes([RFC6962_LEAF_HASH_PREFIX]) + data
        ).digest()  # pylint: disable=line-too-long
        assert leaf_hash == expected_hash

    def test_hasher_hash_children(self) -> None:
        """Test hashing two children nodes."""
        hasher = Hasher(hashlib.sha256)
        left = b"left_node_hash_123456789012345678901234567890ab"[:32]
        right = b"right_node_hash_12345678901234567890123456789ab"[:32]

        result = hasher.hash_children(left, right)

        expected = hashlib.sha256(
            bytes([RFC6962_NODE_HASH_PREFIX]) + left + right
        ).digest()
        assert result == expected

    def test_hasher_size(self) -> None:
        """Test getting hash size."""
        hasher = Hasher(hashlib.sha256)
        assert hasher.size() == 32

    def test_default_hasher(self) -> None:
        """Test default hasher is SHA256."""
        assert DefaultHasher.hash_func == hashlib.sha256


class TestRootMismatchError:
    """Test RootMismatchError exception."""

    def test_root_mismatch_error_creation(self) -> None:
        """Test creating RootMismatchError."""
        expected = b"expected_root_hash_here_123456"
        calculated = b"calculated_root_hash_here_1234"

        error = RootMismatchError(expected, calculated)

        assert error.expected_root is not None
        assert error.calculated_root is not None
        assert "does not match" in str(error)


class TestVerifyMatch:
    """Test verify_match function."""

    def test_verify_match_success(self) -> None:
        """Test matching roots pass verification."""
        root1 = b"identical_root_hash_12345678"
        root2 = b"identical_root_hash_12345678"
        verify_match(root1, root2)  # Should not raise

    def test_verify_match_failure(self) -> None:
        """Test mismatching roots raise error."""
        root1 = b"root_hash_one_123456789012"
        root2 = b"root_hash_two_123456789012"

        with pytest.raises(RootMismatchError):
            verify_match(root1, root2)


class TestDecompInclProof:
    """Test decomp_incl_proof function."""

    def test_decomp_incl_proof_basic(self) -> None:
        """Test basic inclusion proof decomposition."""
        inner, border = decomp_incl_proof(0, 8)
        assert isinstance(inner, int)
        assert isinstance(border, int)

    def test_decomp_incl_proof_various_sizes(self) -> None:
        """Test decomposition with various tree sizes."""
        # Test different index and size combinations
        inner1, border1 = decomp_incl_proof(5, 8)
        assert inner1 >= 0
        assert border1 >= 0

        inner2, border2 = decomp_incl_proof(3, 16)
        assert inner2 >= 0
        assert border2 >= 0


class TestInnerProofSize:
    """Test inner_proof_size function."""

    def test_inner_proof_size_basic(self) -> None:
        """Test basic inner proof size calculation."""
        size = inner_proof_size(0, 1)
        assert size >= 0

    def test_inner_proof_size_various_inputs(self) -> None:
        """Test inner proof size with various inputs."""
        size1 = inner_proof_size(5, 8)
        assert size1 >= 0

        size2 = inner_proof_size(7, 16)
        assert size2 >= 0


class TestChainFunctions:
    """Test chain_inner, chain_inner_right, and chain_border_right functions."""

    def test_chain_inner_empty_proof(self) -> None:
        """Test chaining with empty proof."""
        seed = b"seed_hash_12345678901234567890123456789012"[:32]
        proof: list[bytes] = []
        result = chain_inner(DefaultHasher, seed, proof, 0)
        assert result == seed

    def test_chain_inner_with_proof(self) -> None:
        """Test chaining with proof hashes."""
        seed = b"seed_hash_12345678901234567890123456789012"[:32]
        proof = [b"proof_hash_1234567890123456789012345678"[:32]]
        result = chain_inner(DefaultHasher, seed, proof, 0)
        assert len(result) == 32

    def test_chain_inner_right_empty_proof(self) -> None:
        """Test right chaining with empty proof."""
        seed = b"seed_hash_12345678901234567890123456789012"[:32]
        proof: list[bytes] = []
        result = chain_inner_right(DefaultHasher, seed, proof, 0)
        assert result == seed

    def test_chain_border_right_empty_proof(self) -> None:
        """Test border right chaining with empty proof."""
        seed = b"seed_hash_12345678901234567890123456789012"[:32]
        proof: list[bytes] = []
        result = chain_border_right(DefaultHasher, seed, proof)
        assert result == seed

    def test_chain_border_right_with_proof(self) -> None:
        """Test border right chaining with proof."""
        seed = b"seed_hash_12345678901234567890123456789012"[:32]
        proof = [
            b"proof_hash_1234567890123456789012345678"[:32],
            b"proof_hash_2345678901234567890123456789"[:32],
        ]
        result = chain_border_right(DefaultHasher, seed, proof)
        assert len(result) == 32


class TestRootFromInclusionProof:
    """Test root_from_inclusion_proof function."""

    def test_root_from_inclusion_proof_index_beyond_size(self) -> None:
        """Test error when index is beyond tree size."""
        leaf_hash = b"leaf_hash_123456789012345678901234"[:32]
        proof: list[bytes] = []

        with pytest.raises(ValueError, match="index is beyond size"):
            root_from_inclusion_proof(DefaultHasher, 10, 5, leaf_hash, proof)

    def test_root_from_inclusion_proof_invalid_leaf_size(self) -> None:
        """Test error with invalid leaf hash size."""
        leaf_hash = b"short"  # Too short for SHA256
        proof: list[bytes] = []

        with pytest.raises(ValueError, match="leaf_hash has unexpected size"):
            root_from_inclusion_proof(DefaultHasher, 0, 1, leaf_hash, proof)

    def test_root_from_inclusion_proof_wrong_proof_size(self) -> None:
        """Test error with wrong proof size."""
        leaf_hash = b"leaf_hash_123456789012345678901234"[:32]
        proof = [b"proof_hash_12345678901234567890123"[:32]]

        with pytest.raises(ValueError, match="wrong proof size"):
            root_from_inclusion_proof(DefaultHasher, 0, 8, leaf_hash, proof)

    def test_root_from_inclusion_proof_single_leaf(self) -> None:
        """Test root computation for single leaf tree."""
        leaf_hash = b"a" * 32
        proof: list[bytes] = []

        result = root_from_inclusion_proof(DefaultHasher, 0, 1, leaf_hash, proof)
        assert result == leaf_hash


class TestVerifyInclusion:
    """Test verify_inclusion function."""

    def test_verify_inclusion_matching_roots(self) -> None:
        """Test inclusion verification with matching roots."""
        leaf_hash = "a" * 64
        root = "a" * 64
        proof: list[str] = []

        verify_inclusion(DefaultHasher, 0, 1, leaf_hash, proof, root)

    def test_verify_inclusion_mismatching_roots(self) -> None:
        """Test inclusion verification with mismatching roots."""
        leaf_hash = "a" * 64
        root = "b" * 64
        proof: list[str] = []

        with pytest.raises(RootMismatchError):
            verify_inclusion(DefaultHasher, 0, 1, leaf_hash, proof, root)


class TestVerifyConsistency:
    """Test verify_consistency function."""

    def test_verify_consistency_equal_sizes_empty_proof(self) -> None:
        """Test consistency with equal tree sizes."""
        root1 = "a" * 64
        root2 = "a" * 64
        proof: list[str] = []

        verify_consistency(DefaultHasher, 100, 100, proof, root1, root2)

    def test_verify_consistency_equal_sizes_non_empty_proof(self) -> None:
        """Test consistency error with equal sizes but non-empty proof."""
        root1 = "a" * 64
        root2 = "a" * 64
        proof = ["b" * 64]

        with pytest.raises(
            ValueError, match="size1=size2, but bytearray_proof is not empty"
        ):  # pylint: disable=line-too-long
            verify_consistency(DefaultHasher, 100, 100, proof, root1, root2)

    def test_verify_consistency_size2_less_than_size1(self) -> None:
        """Test consistency error when size2 < size1."""
        root1 = "a" * 64
        root2 = "b" * 64
        proof: list[str] = []

        with pytest.raises(ValueError, match="size2 .* < size1"):
            verify_consistency(DefaultHasher, 200, 100, proof, root1, root2)

    def test_verify_consistency_size1_zero_empty_proof(self) -> None:
        """Test consistency with size1=0 and empty proof."""
        root1 = "a" * 64
        root2 = "b" * 64
        proof: list[str] = []

        verify_consistency(DefaultHasher, 0, 100, proof, root1, root2)

    def test_verify_consistency_size1_zero_non_empty_proof(self) -> None:
        """Test consistency error with size1=0 but non-empty proof."""
        root1 = "a" * 64
        root2 = "b" * 64
        proof = ["c" * 64]

        with pytest.raises(
            ValueError, match="expected empty bytearray_proof, but got 1 components"
        ):
            verify_consistency(DefaultHasher, 0, 100, proof, root1, root2)

    def test_verify_consistency_empty_proof_error(self) -> None:
        """Test consistency error with empty proof when proof is required."""
        root1 = "a" * 64
        root2 = "b" * 64
        proof: list[str] = []

        with pytest.raises(ValueError, match="empty bytearray_proof"):
            verify_consistency(DefaultHasher, 50, 100, proof, root1, root2)


class TestComputeLeafHash:
    """Test compute_leaf_hash function."""

    def test_compute_leaf_hash_basic(self) -> None:
        """Test basic leaf hash computation."""
        # Base64 encode some test data
        test_data = {"test": "data"}
        import json  # pylint: disable=import-outside-toplevel

        encoded_body = base64.b64encode(json.dumps(test_data).encode()).decode()

        result = compute_leaf_hash(encoded_body)

        assert isinstance(result, str)
        assert len(result) == 64  # SHA256 hex digest is 64 characters

    def test_compute_leaf_hash_consistency(self) -> None:
        """Test that same input produces same hash."""
        encoded_body = base64.b64encode(b"test data").decode()

        result1 = compute_leaf_hash(encoded_body)
        result2 = compute_leaf_hash(encoded_body)

        assert result1 == result2

    def test_compute_leaf_hash_includes_prefix(self) -> None:
        """Test that leaf hash includes RFC6962 prefix."""
        test_bytes = b"test data"
        encoded_body = base64.b64encode(test_bytes).decode()

        result = compute_leaf_hash(encoded_body)

        # Manually compute expected hash with prefix
        expected = hashlib.sha256(
            bytes([RFC6962_LEAF_HASH_PREFIX]) + test_bytes
        ).hexdigest()  # pylint: disable=line-too-long
        assert result == expected
