#!/bin/bash

# Seetle CLI Test Script
# This script tests the release binary with different backend combinations.

set -e

BINARY="./target/release/seetle"
STORAGE_DIR="test-metadata-cli"
MSG="Hello, Seetle!"

# Check if binary exists
if [ ! -f "$BINARY" ]; then
    echo "Release binary not found at $BINARY. Building..."
    cargo build --release
fi

# Cleanup function
cleanup() {
    echo "Cleaning up $STORAGE_DIR..."
    rm -rf "$STORAGE_DIR"
}

# Ensure cleanup on exit
trap cleanup EXIT

# Test function
# Usage: run_test <root_backend> <storage_wrapper>
run_test() {
    local root=$1
    local wrapper=$2
    local id="test-key-${root}-${wrapper}"
    
    echo ""
    echo "=================================================="
    echo "Testing Backend Combo: Root=$root, Wrapper=$wrapper"
    echo "=================================================="
    
    # 1. Generate Key
    echo "[1/3] Generating Ed25519 key..."
    $BINARY --storage-dir "$STORAGE_DIR" --root-backend "$root" --storage-wrapper "$wrapper" \
        generate-key --identifier "$id" --algorithm Ed25519 || return 1
        
    # 2. Sign
    echo "[2/3] Signing data..."
    # Capture the signature output and extract the hex value
    SIG_OUT=$($BINARY --storage-dir "$STORAGE_DIR" --root-backend "$root" --storage-wrapper "$wrapper" \
        sign --identifier "$id" --data "$MSG") || return 1
    
    echo "$SIG_OUT"
    SIG=$(echo "$SIG_OUT" | grep "Signature (hex):" | awk '{print $3}')
    
    if [ -z "$SIG" ]; then
        echo "Error: Failed to extract signature from output"
        return 1
    fi
    
    # 3. Verify
    echo "[3/3] Verifying signature..."
    VERIFY_OUT=$($BINARY --storage-dir "$STORAGE_DIR" --root-backend "$root" --storage-wrapper "$wrapper" \
        verify --identifier "$id" --data "$MSG" --signature "$SIG") || return 1
    
    echo "$VERIFY_OUT"
    if [[ "$VERIFY_OUT" == *"Verified: true"* ]]; then
        echo "Result: SUCCESS"
    else
        echo "Result: FAILURE"
        return 1
    fi
}

# Run tests
echo "Starting backend tests with $BINARY..."

# 1. Mock Root with No Wrapper (Baseline)
run_test "mock" "none"

# 2. Keyring (Optional, depends on system environment)
echo ""
echo "Attempting Keyring test..."
if run_test "keyring" "keyring"; then
    echo "Keyring test PASSED"
else
    echo "Keyring test SKIPPED or FAILED (Expected if no DBus/Secret Service available)"
fi

# 3. TPM (Optional, depends on hardware and features)
echo ""
echo "Attempting TPM test..."
echo "Note: This requires 'libtss2-dev', 'tpm2-tools', and '--features tpm' during build."
if run_test "tpm" "tpm"; then
    echo "TPM test PASSED"
else
    echo "TPM test SKIPPED or FAILED"
    echo "To test TPM, ensure you have a TPM 2.0 device, 'tpm2-abrmd' (optional but recommended), or a TPM simulator (mssim/swtpm) running, and build with: cargo build --release --features tpm"
    echo "If using direct device access, ensure your user is in the 'tss' group: sudo usermod -aG tss \$USER && newgrp tss"
fi

echo ""
echo "=================================================="
echo "Backend testing sequence finished."
echo "=================================================="
