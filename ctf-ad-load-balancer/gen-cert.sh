#!/bin/sh
# Generate a self-signed cert for HTTPS rules: certs/cert.pem + certs/key.pem
set -e
cd "$(dirname "$0")"
mkdir -p certs
openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
  -keyout certs/key.pem -out certs/cert.pem -subj "/CN=${1:-vulnbox}"
echo "wrote certs/cert.pem certs/key.pem"
