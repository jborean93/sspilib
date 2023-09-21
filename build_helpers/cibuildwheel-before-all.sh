# sspi-rs doesn't have versions, this just needs to be bumped when new changes
# are needed.
# https://github.com/Devolutions/sspi-rs
DEVOLUTIONS_COMMIT_ID="f349cf5c3df35b9e362291bf1526aba4c33d9b0c"

DEVOLUTIONS_LIB_PATH="${LD_LIBRARY_PATH%%:*}"
mkdir -p "${DEVOLUTIONS_LIB_PATH}"

DEVOLUTIONS_PATH="$( dirname "${DEVOLUTIONS_LIB_PATH}" )"

yum install -y \
    gcc \
    libicu-devel \
    unzip \
    wget

echo "Installing rust compiler"
wget --no-verbose -O - https://sh.rustup.rs | bash -s -- -y
source ~/.cargo/env
rustup update

echo "Downloading sspi-rs at commit ${DEVOLUTIONS_COMMIT_ID}"
wget \
    --no-verbose \
    --directory-prefix="${DEVOLUTIONS_PATH}" \
    "https://github.com/Devolutions/sspi-rs/archive/${DEVOLUTIONS_COMMIT_ID}.zip"

echo "Extracting sspi-rs source code"
unzip \
    -q \
    -d "${DEVOLUTIONS_PATH}" \
    "${DEVOLUTIONS_PATH}/${DEVOLUTIONS_COMMIT_ID}.zip"

echo "Compiling sspi-rs release library"
cargo build \
    --manifest-path "${DEVOLUTIONS_PATH}/sspi-rs-${DEVOLUTIONS_COMMIT_ID}/Cargo.toml" \
    --package sspi-ffi \
    --release

mv "${DEVOLUTIONS_PATH}/sspi-rs-${DEVOLUTIONS_COMMIT_ID}/target/release/libsspi.so" "${DEVOLUTIONS_LIB_PATH}/"
