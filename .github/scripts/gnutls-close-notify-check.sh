#!/usr/bin/env bash
#
# Regression check for the TLS close_notify behavior of the FTP server.
#
# .NET's own SslStream client cannot tell the difference between a graceful
# close_notify and a bare socket close: it treats an EOF without a
# close_notify as a clean end of stream too. GnuTLS-based clients (e.g.
# FileZilla, lftp) are strict about this and report
# "The TLS connection was non-properly terminated" when the server does not
# send a close_notify alert before closing the connection.
#
# This script starts the real FTP server (samples/TestFtpServer) with
# explicit TLS enabled, drives it with lftp (which links against GnuTLS on
# Linux), and fails if lftp's debug output reports a non-properly terminated
# connection, or if the expected 226 (transfer complete) replies are
# missing.
#
# Usage: .github/scripts/gnutls-close-notify-check.sh
#
# Can be run locally on Linux (apt-get install lftp) as well as in CI.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK_DIR="$(mktemp -d)"
trap 'cleanup' EXIT

SERVER_PID=""

cleanup() {
    if [[ -n "${SERVER_PID}" ]] && kill -0 "${SERVER_PID}" 2>/dev/null; then
        kill "${SERVER_PID}" 2>/dev/null || true
        wait "${SERVER_PID}" 2>/dev/null || true
    fi
    rm -rf "${WORK_DIR}"
}

PORT=2121
PASV_RANGE="10000:10009"
CERT="${WORK_DIR}/cert.pem"
KEY="${WORK_DIR}/key.pem"
SERVER_LOG="${WORK_DIR}/ftpserver.log"
LFTP_LOG="${WORK_DIR}/lftp.log"
UPLOAD_FILE="${WORK_DIR}/up.txt"

echo "Generating self-signed certificate..."
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "${KEY}" -out "${CERT}" -days 2 -subj "/CN=ftpserver"

echo "hello from gnutls-close-notify-check" > "${UPLOAD_FILE}"

echo "Starting FTP server..."
(
    cd "${REPO_ROOT}/samples/TestFtpServer"
    FTPSERVER_ENVIRONMENT=Production exec dotnet run --no-launch-profile -c Release -- \
        -p "${PORT}" -s "${PASV_RANGE}" --promiscuous \
        -c "${CERT}" -k "${KEY}" in-memory
) > "${SERVER_LOG}" 2>&1 &
SERVER_PID=$!

echo "Waiting for the server to start listening on port ${PORT}..."
for _ in $(seq 1 60); do
    if (exec 3<>"/dev/tcp/127.0.0.1/${PORT}") 2>/dev/null; then
        exec 3<&- 3>&-
        break
    fi
    if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
        echo "Server process exited before it started listening. Log:"
        cat "${SERVER_LOG}"
        exit 1
    fi
    sleep 1
done

if ! (exec 3<>"/dev/tcp/127.0.0.1/${PORT}") 2>/dev/null; then
    echo "Server never started listening on port ${PORT}. Log:"
    cat "${SERVER_LOG}"
    exit 1
fi
exec 3<&- 3>&-

echo "Running lftp against the server..."
set +e
lftp -d \
    -e "set ftp:ssl-force true; set ftp:ssl-protect-data true; set ssl:verify-certificate no; set net:max-retries 1; set net:timeout 20; ls; put ${UPLOAD_FILE}; ls; bye" \
    -u anonymous,test@example.com 127.0.0.1 -p "${PORT}" > "${LFTP_LOG}" 2>&1
LFTP_EXIT=$?
set -e

echo "----- lftp output -----"
cat "${LFTP_LOG}"
echo "------------------------"

FAILED=0

if grep -qi "non-properly terminated" "${LFTP_LOG}"; then
    echo "FAIL: lftp reported a non-properly terminated TLS connection (missing close_notify)."
    FAILED=1
fi

if [[ "$(grep -c "^<--- 226" "${LFTP_LOG}" || true)" -lt 2 ]]; then
    echo "FAIL: expected at least two 226 (transfer complete) replies (LIST + STOR), but found fewer."
    FAILED=1
fi

if [[ ${LFTP_EXIT} -ne 0 ]]; then
    echo "FAIL: lftp exited with status ${LFTP_EXIT}."
    FAILED=1
fi

echo "----- server log -----"
cat "${SERVER_LOG}"
echo "-----------------------"

if [[ ${FAILED} -ne 0 ]]; then
    exit 1
fi

echo "OK: no non-properly-terminated TLS connections detected, all transfers completed."
