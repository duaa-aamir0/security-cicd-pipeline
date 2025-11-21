#!/bin/bash

set -e  # Exit on error

TARGET_URL=${1:-"http://localhost:5000"}
REPORT_DIR="reports"
mkdir -p "$REPORT_DIR"

# run ZAP baseline scan (quick)
docker run --rm --network host -v "$(pwd)/$REPORT_DIR:/zap/wrk:rw" owasp/zap2docker-stable:latest zap-baseline.py \
    -t "$TARGET_URL" -J zap-report.json -r zap-report.html -I || true

echo "ZAP scan reports saved to $REPORT_DIR/"