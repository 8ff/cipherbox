#!/bin/bash

function fail {
  echo "Test failed: $1"
  exit 1
}

dd if=/dev/urandom of=randomData bs=1M count=1000 2>/dev/null || fail "Failed to generate random data"
CKEY=test go run carp.go e < randomData > encryptedData || fail "Failed to encrypt data"
CKEY=test go run carp.go d < encryptedData > decryptedData || fail "Failed to decrypt data"
# Check if on macOS, use md5 instead of md5sum
if [ "$(uname)" == "Darwin" ]; then
  md5 randomData decryptedData || fail "Decrypted data does not match original data"
else
  md5sum randomData decryptedData || fail "Decrypted data does not match original data"
fi
rm randomData encryptedData decryptedData || fail "Failed to clean up"