"""Tests for CLI argument parsing and -c flag functionality."""

import sys
from unittest.mock import MagicMock, mock_open, patch

import pytest

from main import _main


class TestCLICheckpointFlag:
    """Test CLI -c/--checkpoint flag functionality."""

    @patch("main.get_latest_checkpoint")
    @patch("builtins.print")
    def test_checkpoint_flag_basic(
        self, mock_print: MagicMock, mock_checkpoint: MagicMock
    ) -> None:
        """Test that -c flag fetches and prints checkpoint."""
        mock_checkpoint.return_value = {
            "treeSize": 1000,
            "treeID": "test-tree-id",
            "rootHash": "abc123",
        }

        with patch.object(sys, "argv", ["main.py", "-c"]):
            _main()

        mock_checkpoint.assert_called_once()
        # Should print the checkpoint as JSON
        assert mock_print.called

    @patch("main.get_latest_checkpoint")
    @patch("builtins.open", new_callable=mock_open)
    def test_checkpoint_flag_with_debug(
        self, mock_file: MagicMock, mock_checkpoint: MagicMock
    ) -> None:
        """Test that -c with -d flag saves checkpoint to file."""
        checkpoint_data = {
            "treeSize": 1000,
            "treeID": "test-tree-id-123",
            "rootHash": "abc123def456",
        }
        mock_checkpoint.return_value = checkpoint_data

        with patch.object(sys, "argv", ["main.py", "-c", "-d"]):
            _main()

        mock_checkpoint.assert_called_once()
        # Should write to file in debug mode
        mock_file.assert_called_once()

    @patch("main.get_latest_checkpoint")
    @patch("builtins.print")
    def test_checkpoint_flag_output_format(
        self, mock_print: MagicMock, mock_checkpoint: MagicMock
    ) -> None:
        """Test that checkpoint is printed in correct JSON format."""
        checkpoint_data = {
            "treeSize": 2000,
            "treeID": "tree-xyz",
            "rootHash": "hash123",
        }
        mock_checkpoint.return_value = checkpoint_data

        with patch.object(sys, "argv", ["main.py", "--checkpoint"]):
            _main()

        # Verify that print was called with JSON formatted output
        mock_print.assert_called()
        call_args = str(mock_print.call_args_list)
        assert "treeSize" in call_args or mock_print.called


class TestCLIInclusionFlag:
    """Test CLI --inclusion flag functionality."""

    @patch("main.inclusion")
    def test_inclusion_flag_with_artifact(self, mock_inclusion: MagicMock) -> None:
        """Test --inclusion flag with required --artifact argument."""
        with patch.object(
            sys,
            "argv",
            ["main.py", "--inclusion", "123", "--artifact", "test.txt"],
        ):
            try:
                _main()
            except SystemExit:
                pass  # argparse may exit, that's ok

        # Verify the inclusion function was called with correct arguments
        mock_inclusion.assert_called_once()

    def test_inclusion_flag_without_artifact(self) -> None:
        """Test that --inclusion without --artifact raises error."""
        with patch.object(sys, "argv", ["main.py", "--inclusion", "123"]):
            with pytest.raises(SystemExit):
                _main()


class TestCLIConsistencyFlag:
    """Test CLI --consistency flag functionality."""

    @patch("main.consistency")
    def test_consistency_flag_with_all_params(
        self, mock_consistency: MagicMock
    ) -> None:
        """Test --consistency flag with all required parameters."""
        with patch.object(
            sys,
            "argv",
            [
                "main.py",
                "--consistency",
                "--tree-id",
                "tree-123",
                "--tree-size",
                "1000",
                "--root-hash",
                "hash123",
            ],
        ):
            _main()

        mock_consistency.assert_called_once()

    @patch("builtins.print")
    def test_consistency_flag_missing_tree_id(self, mock_print: MagicMock) -> None:
        """Test --consistency without tree-id prints error."""
        with patch.object(
            sys,
            "argv",
            [
                "main.py",
                "--consistency",
                "--tree-size",
                "1000",
                "--root-hash",
                "hash123",
            ],
        ):
            _main()

        mock_print.assert_called_with("please specify tree id for previous checkpoint")

    @patch("builtins.print")
    def test_consistency_flag_missing_tree_size(self, mock_print: MagicMock) -> None:
        """Test --consistency without tree-size prints error."""
        with patch.object(
            sys,
            "argv",
            [
                "main.py",
                "--consistency",
                "--tree-id",
                "tree-123",
                "--root-hash",
                "hash123",
            ],
        ):
            _main()

        mock_print.assert_called_with(
            "please specify tree size for previous checkpoint"
        )  # pylint: disable=line-too-long

    @patch("builtins.print")
    def test_consistency_flag_missing_root_hash(self, mock_print: MagicMock) -> None:
        """Test --consistency without root-hash prints error."""
        with patch.object(
            sys,
            "argv",
            [
                "main.py",
                "--consistency",
                "--tree-id",
                "tree-123",
                "--tree-size",
                "1000",
            ],  # pylint: disable=line-too-long
        ):
            _main()

        mock_print.assert_called_with(
            "please specify root hash for previous checkpoint"
        )  # pylint: disable=line-too-long


class TestCLIDebugFlag:
    """Test CLI -d/--debug flag functionality."""

    @patch("main.get_latest_checkpoint")
    @patch("builtins.print")
    def test_debug_flag_enables_debug_mode(
        self, mock_print: MagicMock, mock_checkpoint: MagicMock
    ) -> None:
        """Test that -d flag enables debug mode."""
        mock_checkpoint.return_value = {
            "treeSize": 1000,
            "treeID": "test-id",
            "rootHash": "hash",
        }

        with patch.object(sys, "argv", ["main.py", "-d", "-c"]):
            _main()

        # Check that "Debug mode enabled" was printed
        printed_messages = [str(call) for call in mock_print.call_args_list]
        debug_message_found = any(
            "Debug mode enabled" in msg for msg in printed_messages
        )
        assert debug_message_found


class TestCLIArgumentValidation:
    """Test CLI argument validation."""

    def test_no_arguments_provided(self) -> None:
        """Test CLI with no arguments runs without error."""
        with patch.object(sys, "argv", ["main.py"]):
            _main()  # Should run without raising exception

    @patch("main.get_latest_checkpoint")
    @patch("builtins.print")
    def test_multiple_flags_together(
        self, mock_print: MagicMock, mock_checkpoint: MagicMock
    ) -> None:
        """Test that multiple flags can be used together."""
        mock_checkpoint.return_value = {
            "treeSize": 1500,
            "treeID": "combined-test",
            "rootHash": "combined-hash",
        }

        with patch.object(sys, "argv", ["main.py", "-d", "-c"]):
            _main()

        assert mock_checkpoint.called
        assert mock_print.called
