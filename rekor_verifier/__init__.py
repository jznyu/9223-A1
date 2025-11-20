"""Rekor transparency log verifier for inclusion and consistency proofs."""

from rekor_verifier.main import (
    consistency,
    get_consistency_proof,
    get_latest_checkpoint,
    get_log_entry,
    get_verification_proof,
    inclusion,
)
from rekor_verifier.merkle_proof import (
    DefaultHasher,
    Hasher,
    RootMismatchError,
    compute_leaf_hash,
    verify_consistency,
    verify_inclusion,
)
from rekor_verifier.util import extract_public_key, verify_artifact_signature

__version__ = "4.0.0"

__all__ = [
    # Main functions
    "consistency",
    "get_consistency_proof",
    "get_latest_checkpoint",
    "get_log_entry",
    "get_verification_proof",
    "inclusion",
    # Merkle proof functions
    "DefaultHasher",
    "Hasher",
    "RootMismatchError",
    "compute_leaf_hash",
    "verify_consistency",
    "verify_inclusion",
    # Utility functions
    "extract_public_key",
    "verify_artifact_signature",
    "__version__",
]
