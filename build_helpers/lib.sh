#!/bin/bash

lib::setup::system_requirements() {
    if [ x"${GITHUB_ACTIONS}" = "xtrue" ]; then
        echo "::group::Installing System Requirements"
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
    if lib::is_windows; then
        echo "Running the tests with an Obol KDC for the Kerberos tests"
        pwsh -NoProfile -NonInteractive -File build_helpers/run-with-kdc.ps1 \
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
