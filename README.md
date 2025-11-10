# Description
This project provides a way to verify the Rekor transparency log, which records artifact signatures to provide tamper-proof evidence that something was signed at a specific time.

There are three main verfifcation operations that can be performed:
1. Checkpoint Retrieval (--checkpoint)
This fetches the latest state of the Rekor transparency log, including:
• Tree size (number of entries)
• Root hash (cryptographic commitment to all entries)
• Tree ID

2. Inclusion Proof Verification (--inclusion)
This proves that a specific artifact exists in the transparency log by:
• Fetching a log entry by index from Rekor
• Extracting the signature and certificate from the entry
• Verifying the artifact's digital signature using ECDSA with the public key
• Computing a Merkle tree inclusion proof to cryptographically prove the entry is in the log
• Checking if it's included in the latest checkpoint

3. Consistency Proof Verification (--consistency)
This proves that the transparency log hasn't been tampered with over time by:
• Comparing an older checkpoint with the current checkpoint
• Verifying the Merkle tree consistency proof ensures no entries were removed or modified

# Installation Steps
To sign artifacts and verify signatures using Sigstore, you need to install Cosign:
• Go to https://docs.sigstore.dev/cosign/system_config/installation/ for installation instructions appropriate to your system.

# Usage Instructions
1. Create an artifact:

For example, I can create an `artifact.md` file and type in "Hello World". Typical artifacts can be container images, software binaries, source code tarballs, package manifests, among other things. Though an artifact can be anything software-related that you want to verify the integrity of.

2. Using the cosign tool (check #Installation Steps for more info), sign the artifact via Terminal:
`cosign sign-blob <file-name> --bundle artifact.sigstore.bundle`

This will prompt you to verify your identity. And once your identity is verified, an ephemeral certificate is generated, artifact is signed and its signature is uploaded to transparency log.


# Necessary Dependencies

Just the cosign tool which is reference in #Installation Steps.