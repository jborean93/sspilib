#!/bin/bash

# The version of https://www.powershellgallery.com/packages/Obol installed to
# run a KDC for the Kerberos tests when the module is not already present.
OBOL_VERSION="0.1.0-beta1"

lib::setup::system_requirements() {
    if [ x"${GITHUB_ACTIONS}" = "xtrue" ]; then
        echo "::group::Installing System Requirements"
    fi

    if ! lib::is_windows; then
        echo "Not running on Windows, the Kerberos tests will be skipped"
    elif command -v pwsh > /dev/null 2>&1; then
        echo "Checking the Obol PowerShell module for the Kerberos tests is installed"
        pwsh -NoProfile -NonInteractive -File build_helpers/install-obol.ps1 -Version "${OBOL_VERSION}"
    else
        echo "pwsh is not available, the Kerberos tests will be skipped"
    fi

    if [ x"${GITHUB_ACTIONS}" = "xtrue" ]; then
        echo "::endgroup::"
    fi
}

lib::setup::python_requirements() {
    if [ x"${GITHUB_ACTIONS}" = "xtrue" ]; then
        echo "::group::Installing Python Requirements"
    fi

    echo "Installing sspilib"

    # Getting the version is important so that pip prioritises our local dist
    python -m pip install build
    SSPI_VERSION="$( grep -m 1 version pyproject.toml | tr -s ' ' | tr -d '"' | tr -d "'" | cut -d' ' -f3 )"

    python -m pip install sspilib=="${SSPI_VERSION}" \
        --find-links dist \
        --verbose

    echo "Installing dev dependencies"
    python -m pip install -r requirements-dev.txt

    if [ x"${GITHUB_ACTIONS}" = "xtrue" ]; then
        echo "::endgroup::"
    fi
}

lib::sanity::run() {
    if [ x"${GITHUB_ACTIONS}" = "xtrue" ]; then
        echo "::group::Running Sanity Checks"
    fi

    python -m black . --check
    python -m isort . --check-only
    python -m mypy .

    if [ x"${GITHUB_ACTIONS}" = "xtrue" ]; then
        echo "::endgroup::"
    fi
}

lib::tests::run() {
    if [ x"${GITHUB_ACTIONS}" = "xtrue" ]; then
        echo "::group::Running Tests"
    fi

    PYTEST_ARGS=(
        -v
        --junitxml junit/test-results.xml
    )

    # The Kerberos tests are Windows only, sspi-rs cannot accept Kerberos
    # tokens or use keytab credentials. The Obol KDC runs in the pwsh process
    # that starts pytest so it must wrap the whole run.
    if lib::is_windows && lib::kerberos::available; then
        echo "Running the tests with an Obol KDC for the Kerberos tests"
        pwsh -NoProfile -NonInteractive -File build_helpers/kerberos-env.ps1 \
            python -m pytest "${PYTEST_ARGS[@]}"
    else
        echo "Running the tests without a KDC, the Kerberos tests will be skipped"
        python -m pytest "${PYTEST_ARGS[@]}"
    fi

    if [ x"${GITHUB_ACTIONS}" = "xtrue" ]; then
        echo "::endgroup::"
    fi
}

lib::is_windows() {
    [ "${OS:-}" = "Windows_NT" ]
}

lib::kerberos::available() {
    command -v pwsh > /dev/null 2>&1 || return 1

    pwsh -NoProfile -NonInteractive -Command 'Import-Module -Name Obol -ErrorAction Stop' > /dev/null 2>&1
}
