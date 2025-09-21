""" 
4. Implement code to fetch the entry details from the Rekor log given log index.

5. Extract signature and certificate from the log entry. (Note: Entries are stored in base64 encoded format in the log, will need to decode them)

6. Extract public key from the certificate using the given utility function `extract_public_key`

7. Using the obtained signature and public key from the transparency log entry, verify the validity of the signature given artifact using the utility function `verify_artifact_signature`.

8. Using the entry details obtained earlier, use the `verification → inclusionProof` keys to obtain the `leaf_hash`,`index`,`root_hash`,`tree_size`, and `hashes` list and pass it to the `verify_inclusion` function from `merkle_proof.py` to verify the merkle proof.

"""
import argparse
import json
import requests
import base64
import os
from util import extract_public_key, verify_artifact_signature
from merkle_proof import DefaultHasher, compute_leaf_hash, verify_inclusion

REKOR_BASE_URL = "https://rekor.sigstore.dev"

def _require_positive_int(value):
    if not isinstance(value, int) or value < 0:
        raise ValueError(f"Log index must be a non-negative integer")

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
    return signature,certificate_pem, payload

def get_log_entry(log_index, debug=False):
    # _require_positive_int(log_index)
    entry = _get_entry_index(log_index)
    if debug:
        print(json.dumps(entry, indent=2))
    return entry

def get_verification_proof(log_index: int, debug=False) -> dict:
    # _require_positive_int(log_index)

    entry = get_log_entry(log_index, debug)
    payload = next(iter(entry.values()))
    inclusion_proof = payload["verification"]["inclusionProof"]

    index = inclusion_proof["logIndex"]
    root_hash = inclusion_proof["rootHash"]
    tree_size = inclusion_proof["treeSize"]
    hashes = inclusion_proof["hashes"]
    leaf_hash = compute_leaf_hash(payload["body"])

    if debug:
        print(json.dumps({
            "index": index,
            "root_hash": root_hash,
            "tree_size": tree_size,
            "hashes": hashes,
            "leaf_hash": leaf_hash
        }))

    return index, root_hash, tree_size, hashes, leaf_hash

def inclusion(log_index: int, artifact_filepath: str, debug=False) -> bool:
    _require_positive_int(log_index)
    if not artifact_filepath or not os.path.isfile(artifact_filepath):
        raise FileNotFoundError(f"Artifact file not found at: {artifact_filepath}")

    entry = get_log_entry(log_index, debug)
    signature, certificate_pem, _ = _extract_sig_and_cert_from_entry(entry)
    public_key_pem = extract_public_key(certificate_pem)

    if not verify_artifact_signature(signature, public_key_pem, artifact_filepath):
        raise ValueError(f"Artifact signature verification failed")

    index, root_hash, tree_size, hashes, leaf_hash = get_verification_proof(log_index, debug)

    verify_inclusion(DefaultHasher, index, tree_size, leaf_hash, hashes, root_hash, debug=False)



def _main() -> None:
    parser = argparse.ArgumentParser(description="Fetch a Rekor log entry by index")
    parser.add_argument("--index", type=int, required=True, help="log index to fetch")
    args = parser.parse_args()

    inclusion(args.index, "artifact.md", debug=True)

    # entry = get_log_entry(args.index)
    # print(json.dumps(entry, indent=2))
    # signature, certificate_pem, _ = _extract_sig_and_cert_from_entry(entry) 
    # print(f"signature: {signature}")
    # print(f"signature type: {type(signature)}")
    # print(f"================================================")
    # print(f"certificate_ipem: {certificate_pem}")
    # print(f"certificate_pem type: {type(certificate_pem)}")
    # print(f"================================================")
    # public_key = extract_public_key(certificate_pem)
    # print(f"public_key: {public_key}")
    # print(f"public_key type: {type(public_key)}")
    # print(f"================================================")
    # verify_artifact_signature(signature, public_key, "artifact.md")
    # inclusion(args.index, "artifact.md")
if __name__ == "__main__":
    _main()