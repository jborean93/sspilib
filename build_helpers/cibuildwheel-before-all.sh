set -ex

# sspi-rs doesn't have versions, this just needs to be bumped when new changes
# are needed.
# https://github.com/Devolutions/sspi-rs
DEVOLUTIONS_COMMIT_ID="d7b9ff6ffd2157c2f40953c5afc645a7ae203a1e"

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

SSPILIB_INCLUDE_PATH="${CPATH%%:*}"
SSPILIB_LIB_PATH="${LIBRARY_PATH%%:*}"

mkdir -p "${SSPILIB_INCLUDE_PATH}"
mkdir -p "${SSPILIB_LIB_PATH}"

SSPILIB_PATH="$( dirname "${SSPILIB_LIB_PATH}" )"

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
    --directory-prefix="${SSPILIB_PATH}" \
    "https://github.com/unicode-org/icu/releases/download/release-$( echo ${ICU_VERSION} | sed 's/\./-/' )/icu4c-$( echo ${ICU_VERSION} | sed 's/\./_/' )-src.tgz"

tar -xf \
    "${SSPILIB_PATH}"/icu4c-*-src.tgz \
    -C "${SSPILIB_PATH}"

mkdir -p "${SSPILIB_PATH}/icu-native"
pushd "${SSPILIB_PATH}/icu-native"

CFLAGS="${ICU_CFLAGS}" CXXFLAGS="${ICU_CXXFLAGS} ${CFLAGS}" \
    "${SSPILIB_PATH}/icu/source/configure" \
    "${ICU_CONFIGURE_FLAGS[@]}"

make -j${CPUS}

popd

cp "${SSPILIB_PATH}"/icu-native/lib/*.a "${SSPILIB_LIB_PATH}/"

echo "Copying header files to shared include dir"
cp -R "${SSPILIB_PATH}"/icu/source/common/* "${CPATH}"

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
    --directory-prefix="${SSPILIB_PATH}" \
    "https://github.com/Devolutions/sspi-rs/archive/${DEVOLUTIONS_COMMIT_ID}.zip"

echo "Extracting sspi-rs source code"
unzip \
    -q \
    -d "${SSPILIB_PATH}" \
    "${SSPILIB_PATH}/${DEVOLUTIONS_COMMIT_ID}.zip"

SSPI_RS_OPTIONS=(
    "--manifest-path"
    "${SSPILIB_PATH}/sspi-rs-${DEVOLUTIONS_COMMIT_ID}/Cargo.toml"
    "--package"
    "sspi-ffi"
    "--release"
)
SSPI_RS_TARGET_DIR="release"

echo "Compiling sspi-rs release library"
cargo build "${SSPI_RS_OPTIONS[@]}"

cp "${SSPILIB_PATH}/sspi-rs-${DEVOLUTIONS_COMMIT_ID}/target/${SSPI_RS_TARGET_DIR}/libsspi.${LIB_EXT}" \
    "${SSPILIB_LIB_PATH}/"
