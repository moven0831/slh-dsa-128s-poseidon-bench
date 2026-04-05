#!/bin/bash

usage() {
  echo "Usage: $0 {jwt|jwt_1k|jwt_2k|jwt_4k|jwt_8k|show|ecdsa|all|all-sizes}"
  echo "  jwt:       Compile the legacy JWT circuit."
  echo "  jwt_1k:    Compile JWT circuit (1KB - maxMsg=1024)."
  echo "  jwt_2k:    Compile JWT circuit (2KB - maxMsg=2048)."
  echo "  jwt_4k:    Compile JWT circuit (4KB - maxMsg=4096)."
  echo "  jwt_8k:    Compile JWT circuit (8KB - maxMsg=8192)."
  echo "  show:      Compile Show circuit."
  echo "  ecdsa:     Compile ECDSA circuit."
  echo "  all:       Compile jwt + show + ecdsa."
  echo "  all-sizes: Compile jwt_1k + jwt_2k + jwt_4k + jwt_8k."
  exit 1
}

if [ -z "$1" ]; then
  echo "Error: No option provided."
  usage
fi

# Generic compile function for any named circuit
compile_circuit() {
  local name="$1"
  echo "Compiling circuit: $name"
  npx circomkit compile "$name" || { echo "Error: Failed to compile $name."; exit 1; }
  cd "build/$name/" || { echo "Error: 'build/$name/' directory not found."; exit 1; }
  cp "$name.r1cs" "${name}_js/" || { echo "Error: Failed to copy $name.r1cs."; exit 1; }
  cd ../.. || exit 1
  mkdir -p build/cpp || { echo "Error: Failed to create cpp directory."; exit 1; }
  cp -f "build/$name/${name}_cpp/$name.cpp" "build/cpp/$name.cpp" || {
    echo "Error: Failed to sync build/cpp/$name.cpp.";
    exit 1;
  }
  cp -f "build/$name/${name}_cpp/$name.dat" "build/cpp/$name.dat" || {
    echo "Error: Failed to sync build/cpp/$name.dat.";
    exit 1;
  }
  echo "$name compilation complete."
}

case "$1" in
  jwt|jwt_1k|jwt_2k|jwt_4k|jwt_8k|show|ecdsa)
    compile_circuit "$1"
    ;;
  all)
    echo "Compiling all circuits (jwt + show + ecdsa)..."
    compile_circuit jwt
    compile_circuit show
    compile_circuit ecdsa
    echo "All circuits compiled successfully."
    ;;
  all-sizes)
    echo "Compiling all JWT size variants..."
    compile_circuit jwt_1k
    compile_circuit jwt_2k
    compile_circuit jwt_4k
    compile_circuit jwt_8k
    echo "All JWT size variants compiled successfully."
    ;;
  *)
    echo "Error: Invalid option '$1'."
    usage
    ;;
esac
