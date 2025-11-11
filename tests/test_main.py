"""Tests for main.py functionality."""

import json
import tempfile
from unittest.mock import MagicMock, patch, mock_open

import pytest

from main import (
    _get_entry_index,
    _require_positive_int,
    get_latest_checkpoint,
    get_log_entry,
    get_verification_proof,
    get_consistency_proof,
    inclusion,
    consistency,
)


class TestRequirePositiveInt:
    """Test _require_positive_int function."""

    def test_valid_positive_int(self) -> None:
        """Test that positive integers are accepted."""
        _require_positive_int(0)
        _require_positive_int(1)
        _require_positive_int(100)

    def test_invalid_negative_int(self) -> None:
        """Test that negative integers raise ValueError."""
        with pytest.raises(ValueError, match="Log index must be a non-negative integer"):
            _require_positive_int(-1)

    def test_invalid_string(self) -> None:
        """Test that strings raise ValueError."""
        with pytest.raises(ValueError, match="Log index must be a non-negative integer"):
            _require_positive_int("10")  # type: ignore


class TestGetEntryIndex:
    """Test _get_entry_index function."""

    @patch("main.requests.get")
    def test_successful_entry_fetch(self, mock_get: MagicMock) -> None:
        """Test successful fetching of entry by index."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"test": "data"}
        mock_get.return_value = mock_response

        result = _get_entry_index(123)

        assert result == {"test": "data"}
        mock_get.assert_called_once()

    @patch("main.requests.get")
    def test_network_error(self, mock_get: MagicMock) -> None:
        """Test network error handling."""
        mock_get.side_effect = Exception("Network error")

        with pytest.raises(Exception, match="Network error"):
            _get_entry_index(123)


class TestGetLatestCheckpoint:
    """Test get_latest_checkpoint function."""

    @patch("main.requests.get")
    def test_get_latest_checkpoint_success(self, mock_get: MagicMock) -> None:
        """Test successful checkpoint retrieval."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "treeSize": 1000,
            "treeID": "test-tree-id",
            "rootHash": "abc123",
        }
        mock_get.return_value = mock_response

        result = get_latest_checkpoint()

        assert result["treeSize"] == 1000
        assert result["treeID"] == "test-tree-id"
        mock_get.assert_called_once()


class TestGetLogEntry:
    """Test get_log_entry function."""

    @patch("main._get_entry_index")
    def test_get_log_entry_without_debug(self, mock_get_entry: MagicMock) -> None:
        """Test log entry retrieval without debug output."""
        mock_get_entry.return_value = {"entry": "data"}

        result = get_log_entry(123, debug=False)

        assert result == {"entry": "data"}
        mock_get_entry.assert_called_once_with(123)

    @patch("main._get_entry_index")
    @patch("builtins.print")
    def test_get_log_entry_with_debug(
        self, mock_print: MagicMock, mock_get_entry: MagicMock
    ) -> None:
        """Test log entry retrieval with debug output."""
        mock_get_entry.return_value = {"entry": "data"}

        result = get_log_entry(123, debug=True)

        assert result == {"entry": "data"}
        mock_print.assert_called_once()


class TestGetVerificationProof:
    """Test get_verification_proof function."""

    def test_get_verification_proof(self) -> None:
        """Test extraction of verification proof from entry."""
        entry = {
            "test-uuid": {
                "body": "eyJ0ZXN0IjogImRhdGEifQ==",  # base64 encoded {"test": "data"}
                "verification": {
                    "inclusionProof": {
                        "logIndex": 123,
                        "rootHash": "abc123",
                        "treeSize": 1000,
                        "hashes": ["hash1", "hash2"],
                    }
                },
            }
        }

        index, root_hash, tree_size, hashes, leaf_hash = get_verification_proof(entry)

        assert index == 123
        assert root_hash == "abc123"
        assert tree_size == 1000
        assert hashes == ["hash1", "hash2"]
        assert isinstance(leaf_hash, str)


class TestGetConsistencyProof:
    """Test get_consistency_proof function."""

    @patch("main.requests.get")
    def test_get_consistency_proof_basic(self, mock_get: MagicMock) -> None:
        """Test basic consistency proof retrieval."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"hashes": ["hash1", "hash2", "hash3"]}
        mock_get.return_value = mock_response

        result = get_consistency_proof(1000)

        assert result == ["hash1", "hash2", "hash3"]
        mock_get.assert_called_once()

    @patch("main.requests.get")
    def test_get_consistency_proof_with_params(self, mock_get: MagicMock) -> None:
        """Test consistency proof with custom parameters."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"hashes": ["hash1"]}
        mock_get.return_value = mock_response

        result = get_consistency_proof(2000, first_size=1000, tree_id="tree-123")

        assert result == ["hash1"]
        mock_get.assert_called_once()


class TestInclusion:
    """Test inclusion verification function."""

    def test_inclusion_with_invalid_index(self) -> None:
        """Test inclusion with invalid log index."""
        with pytest.raises(ValueError, match="Log index must be a non-negative integer"):
            inclusion(-1, "test.txt")

    def test_inclusion_with_missing_file(self) -> None:
        """Test inclusion with missing artifact file."""
        with pytest.raises(FileNotFoundError):
            inclusion(123, "/nonexistent/file.txt")

    @patch("main.get_latest_checkpoint")
    @patch("main.verify_inclusion")
    @patch("main.get_verification_proof")
    @patch("main.verify_artifact_signature")
    @patch("main.extract_public_key")
    @patch("main._extract_sig_and_cert_from_entry")
    @patch("main.get_log_entry")
    @patch("builtins.print")
    def test_inclusion_successful(
        self,
        mock_print: MagicMock,
        mock_get_log: MagicMock,
        mock_extract: MagicMock,
        mock_extract_key: MagicMock,
        mock_verify_sig: MagicMock,
        mock_get_proof: MagicMock,
        mock_verify_inclusion: MagicMock,
        mock_checkpoint: MagicMock,
    ) -> None:
        """Test successful inclusion verification."""
        # Create a temporary file for testing
        with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
            tmp_file.write(b"test data")
            tmp_path = tmp_file.name

        try:
            mock_get_log.return_value = {"test": "entry"}
            mock_extract.return_value = (b"signature", b"cert", {"payload": "data"})
            mock_extract_key.return_value = b"public_key"
            mock_verify_sig.return_value = True
            mock_get_proof.return_value = (123, "roothash", 1000, ["hash"], "leafhash")
            mock_checkpoint.return_value = {"treeSize": 2000}

            inclusion(123, tmp_path)

            mock_verify_inclusion.assert_called_once()
            mock_checkpoint.assert_called_once()
        finally:
            import os

            os.unlink(tmp_path)


class TestConsistency:
    """Test consistency verification function."""

    @patch("builtins.print")
    def test_consistency_with_empty_checkpoint(self, mock_print: MagicMock) -> None:
        """Test consistency with empty checkpoint."""
        consistency({})
        mock_print.assert_called_once_with("please specify previous checkpoint")

    @patch("main.verify_consistency")
    @patch("main.get_consistency_proof")
    @patch("main.get_latest_checkpoint")
    def test_consistency_successful(
        self,
        mock_latest: MagicMock,
        mock_proof: MagicMock,
        mock_verify: MagicMock,
    ) -> None:
        """Test successful consistency verification."""
        prev_checkpoint = {
            "treeSize": 1000,
            "treeID": "tree-123",
            "rootHash": "hash1",
        }
        mock_latest.return_value = {
            "treeSize": 2000,
            "treeID": "tree-123",
            "rootHash": "hash2",
        }
        mock_proof.return_value = ["proof1", "proof2"]

        consistency(prev_checkpoint)

        mock_verify.assert_called_once()

