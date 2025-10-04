import argparse
import json
import requests
import base64
import os
from util import extract_public_key, verify_artifact_signature
from merkle_proof import (
    DefaultHasher,
    verify_consistency,
    compute_leaf_hash,
    verify_inclusion,
)

REKOR_BASE_URL = "https://rekor.sigstore.dev"


def _require_positive_int(value):
    if not isinstance(value, int) or value < 0:
        raise ValueError("Log index must be a non-negative integer")


def _get_entry_index(log_index: int) -> dict:
    entry_url = f"{REKOR_BASE_URL}/api/v1/log/entries?logIndex={log_index}"
    response = requests.get(entry_url, timeout=10)
    response.raise_for_status()
    return response.json()


def _extract_sig_and_cert_from_entry(entry: dict) -> tuple[bytes, bytes, dict]:
    payload = next(iter(entry.values()))
    body_b64 = payload["body"]
    body_obj = json.loads(base64.b64decode(body_b64))

    try:
        sig_b64 = body_obj["spec"]["signature"]["content"]
        cert_b64 = body_obj["spec"]["signature"]["publicKey"]["content"]
    except KeyError as e:
        raise ValueError(f"Missing key in entry: {e}")

    if not sig_b64 or not cert_b64:
        raise ValueError("Missing signature or certificate in entry")

    signature = base64.b64decode(sig_b64)
    certificate_pem = base64.b64decode(cert_b64)
    return signature, certificate_pem, payload


def get_log_entry(log_index, debug=False):
    # _require_positive_int(log_index)
    entry = _get_entry_index(log_index)
    if debug:
        print(json.dumps(entry, indent=2))
    return entry


def get_verification_proof(entry: dict, debug=False) -> dict:
    # _require_positive_int(log_index)

    payload = next(iter(entry.values()))
    inclusion_proof = payload["verification"]["inclusionProof"]

    index = inclusion_proof["logIndex"]
    root_hash = inclusion_proof["rootHash"]
    tree_size = inclusion_proof["treeSize"]
    hashes = inclusion_proof["hashes"]
    leaf_hash = compute_leaf_hash(payload["body"])

    if debug:
        print(
            json.dumps(
                {
                    "index": index,
                    "root_hash": root_hash,
                    "tree_size": tree_size,
                    "hashes": hashes,
                    "leaf_hash": leaf_hash,
                }
            )
        )

    return index, root_hash, tree_size, hashes, leaf_hash


def inclusion(log_index: int, artifact_filepath: str, debug=False) -> bool:
    # verify that log index and artifact filepath values are sane
    _require_positive_int(log_index)
    if not artifact_filepath or not os.path.isfile(artifact_filepath):
        raise FileNotFoundError(f"Artifact file not found at: {artifact_filepath}")

    entry = get_log_entry(log_index, debug)
    signature, certificate_pem, _ = _extract_sig_and_cert_from_entry(entry)
    public_key_pem = extract_public_key(certificate_pem)

    if not verify_artifact_signature(signature, public_key_pem, artifact_filepath):
        raise ValueError("Artifact signature verification failed")

    index, root_hash, tree_size, hashes, leaf_hash = get_verification_proof(
        entry, debug
    )

    verify_inclusion(
        DefaultHasher, index, tree_size, leaf_hash, hashes, root_hash, debug=True
    )


def get_latest_checkpoint(debug=False):
    entry_url = f"{REKOR_BASE_URL}/api/v1/log"
    response = requests.get(entry_url, timeout=10)
    response.raise_for_status()
    data = response.json()
    return data


def get_consistency_proof(first_size: int, last_size: int, tree_id: str, debug=False):
    url = f"{REKOR_BASE_URL}/api/v1/log/proof"
    params = {"firstSize": first_size, "lastSize": last_size}
    if tree_id:
        params["treeID"] = tree_id
    response = requests.get(url, params=params, timeout=10)
    response.raise_for_status()
    data = response.json()
    hashes = data.get("hashes", [])
    if debug:
        print(
            json.dumps(
                {
                    "firstSize": first_size,
                    "lastSize": last_size,
                    "treeID": tree_id,
                    "hashes": hashes,
                }
            )
        )
    return hashes


def consistency(checkpoint: dict, debug=False):
    # verify that prev checkpoint is not empty
    if not checkpoint:
        print("please specify previous checkpoint")
        return
    # get_latest_checkpoint
    latest_checkpoint = get_latest_checkpoint(debug)
    proof_hashes = get_consistency_proof(
        checkpoint["treeSize"],
        latest_checkpoint["treeSize"],
        checkpoint["treeID"],
        debug,
    )
    verify_consistency(
        DefaultHasher,
        checkpoint["treeSize"],
        latest_checkpoint["treeSize"],
        proof_hashes,
        checkpoint["rootHash"],
        latest_checkpoint["rootHash"],
    )


def _main():
    debug = False
    parser = argparse.ArgumentParser(description="Rekor Verifier")
    parser.add_argument(
        "-d", "--debug", help="Enable debug mode", required=False, action="store_true"
    )
    parser.add_argument(
        "-c",
        "--checkpoint",
        help="Obtain latest checkpoint from Rekor Server public instance",
        required=False,
        action="store_true",
    )
    parser.add_argument(
        "--inclusion",
        help="Verify inclusion of an entry in the Rekor Transparency Log using log index and artifact filepath. Usage: python main.py --inclusion <log index> <artifact filepath>",
        required=False,
        type=int,
    )
    parser.add_argument(
        "--artifact",
        help="Artifact filepath for verifying signature. Usage: python main.py --artifact <artifact filepath>",
        required=False,
    )
    parser.add_argument(
        "--consistency",
        help="Verify consistency of a given previous checkpoint with the latest checkpoint.",
        action="store_true",
    )
    parser.add_argument(
        "--tree-id", help="Tree ID for consistency proof.", required=False
    )
    parser.add_argument(
        "--tree-size", help="Tree size for consistency proof.", required=False, type=int
    )
    parser.add_argument(
        "--root-hash", help="Root hash for consistency proof.", required=False
    )

    args = parser.parse_args()

    if args.inclusion is not None and not args.artifact:
        parser.error("--artifact is required when using --inclusion")

    if args.debug:
        debug = True
        print("Debug mode enabled")
    if args.checkpoint:
        # get and print latest checkpoint from server
        # if debug is enabled, store it in a file checkpoint.json
        checkpoint = get_latest_checkpoint(debug)
        print(json.dumps(checkpoint, indent=4))
        if debug:
            with open(
                f"checkpoint-{checkpoint['treeID']}-{checkpoint['treeSize']}.json", "w"
            ) as f:
                json.dump(checkpoint, f, indent=4)
            print(
                f"Checkpoint stored in checkpoint-{checkpoint['treeID']}-{checkpoint['treeSize']}.json"
            )
    if args.inclusion:
        inclusion(args.inclusion, args.artifact, debug)
        print(
            f"\nInclusion verified for artifact {args.artifact} at log index {args.inclusion}"
        )
    if args.consistency:
        if not args.tree_id:
            print("please specify tree id for previous checkpoint")
            return
        if not args.tree_size:
            print("please specify tree size for previous checkpoint")
            return
        if not args.root_hash:
            print("please specify root hash for previous checkpoint")
            return

        prev_checkpoint = {
            "treeID": args.tree_id,
            "treeSize": args.tree_size,
            "rootHash": args.root_hash,
        }

        consistency(prev_checkpoint, debug)


if __name__ == "__main__":
    _main()
