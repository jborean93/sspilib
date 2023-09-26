set -ex

# sspi-rs doesn't have versions, this just needs to be bumped when new changes
# are needed.
# https://github.com/Devolutions/sspi-rs
DEVOLUTIONS_COMMIT_ID="f349cf5c3df35b9e362291bf1526aba4c33d9b0c"

# Aligns to a release on https://github.com/unicode-org/icu/tree/main
ICU_VERSION="73.2"
ICU_CONFIGURE_FLAGS=(
    "--enable-static=yes"
    "--enable-shared=no"
    "--disable-extras"
    "--disable-tests"
    "--disable-samples"
    "--disable-dyload"
    "--with-data-packaging=static"
)
ICU_CFLAGS="-O3"
ICU_CXXFLAGS=""

PYSSPI_INCLUDE_PATH="${CPATH%%:*}"
PYSSPI_LIB_PATH="${LIBRARY_PATH%%:*}"

mkdir -p "${PYSSPI_INCLUDE_PATH}"
mkdir -p "${PYSSPI_LIB_PATH}"

PYSSPI_PATH="$( dirname "${PYSSPI_LIB_PATH}" )"

if [ "$( uname )" == "Darwin" ]; then
    LIB_EXT="dylib"
    CPUS="$( sysctl -n hw.ncpu )"

    ICU_CXXFLAGS="-stdlib=libc++ -std=c++11"
else
    LIB_EXT="so"
    CPUS="$( nproc )"
    ICU_CFLAGS="-fPIC ${ICU_CFLAGS}"

    yum install -y \
        gcc \
        gcc-c++ \
        unzip \
        wget
fi

wget \
    --no-verbose \
    --directory-prefix="${PYSSPI_PATH}" \
    "https://github.com/unicode-org/icu/releases/download/release-$( echo ${ICU_VERSION} | sed 's/\./-/' )/icu4c-$( echo ${ICU_VERSION} | sed 's/\./_/' )-src.tgz"

tar -xf \
    "${PYSSPI_PATH}"/icu4c-*-src.tgz \
    -C "${PYSSPI_PATH}"

mkdir -p "${PYSSPI_PATH}/icu-native"
pushd "${PYSSPI_PATH}/icu-native"

CFLAGS="${ICU_CFLAGS}" CXXFLAGS="${ICU_CXXFLAGS} ${CFLAGS}" \
    "${PYSSPI_PATH}/icu/source/configure" \
    "${ICU_CONFIGURE_FLAGS[@]}"

make -j${CPUS}

popd

if [ x"${SSPI_BUILD_MACOS_AARCH64:-}" = "xtrue" ]; then
    mkdir -p "${PYSSPI_PATH}/icu-arm64"
    pushd "${PYSSPI_PATH}/icu-arm64"

    CFLAGS="${ICU_CFLAGS} -arch arm64" CXXFLAGS="${ICU_CXXFLAGS} ${CFLAGS}" \
        "${PYSSPI_PATH}/icu/source/configure" \
        "${ICU_CONFIGURE_FLAGS[@]}" \
        --disable-tools \
        --host=arm-apple-darwin \
        --with-cross-build="${PYSSPI_PATH}/icu-native"

    make -j${CPUS}

    popd

    cp "${PYSSPI_PATH}"/icu-arm64/lib/*.a "${PYSSPI_LIB_PATH}/"
else
    cp "${PYSSPI_PATH}"/icu-native/lib/*.a "${PYSSPI_LIB_PATH}/"
fi

echo "Copying header files to shared include dir"
cp -R "${PYSSPI_PATH}"/icu/source/common/* "${CPATH}"

set +e
command -v rustup
RC=$?
set -e
if [ $RC != 0 ]; then
    echo "Installing rust compiler"
    wget --no-verbose -O - https://sh.rustup.rs | bash -s -- -y
    source ~/.cargo/env
    rustup update
fi

echo "Downloading sspi-rs at commit ${DEVOLUTIONS_COMMIT_ID}"
wget \
    --no-verbose \
    --directory-prefix="${PYSSPI_PATH}" \
    "https://github.com/Devolutions/sspi-rs/archive/${DEVOLUTIONS_COMMIT_ID}.zip"

echo "Extracting sspi-rs source code"
unzip \
    -q \
    -d "${PYSSPI_PATH}" \
    "${PYSSPI_PATH}/${DEVOLUTIONS_COMMIT_ID}.zip"

SSPI_RS_OPTIONS=(
    "--manifest-path"
    "${PYSSPI_PATH}/sspi-rs-${DEVOLUTIONS_COMMIT_ID}/Cargo.toml"
    "--package"
    "sspi-ffi"
    "--release"
)
SSPI_RS_TARGET_DIR="release"

if [ x"${SSPI_BUILD_MACOS_AARCH64:-}" = "xtrue" ]; then
    rustup target add aarch64-apple-darwin
    SSPI_RS_OPTIONS+=("--target=aarch64-apple-darwin")
    SSPI_RS_TARGET_DIR="aarch64-apple-darwin/release"
fi

echo "Compiling sspi-rs release library"
cargo build "${SSPI_RS_OPTIONS[@]}"

cp "${PYSSPI_PATH}/sspi-rs-${DEVOLUTIONS_COMMIT_ID}/target/${SSPI_RS_TARGET_DIR}/libsspi.${LIB_EXT}" \
    "${PYSSPI_LIB_PATH}/"
