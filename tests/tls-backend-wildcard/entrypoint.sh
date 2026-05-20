#!/bin/sh
mkdir -p /etc/nginx/certs
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout /etc/nginx/certs/key.pem -out /etc/nginx/certs/cert.pem \
  -days 1 -subj '/CN=*.example.com' \
  -addext 'subjectAltName=DNS:*.example.com,DNS:example.com' 2>/dev/null
exec nginx -g 'daemon off;'
