# Generate self-signed TLS certificates
openssl req -x509 -nodes -newkey ec:<(openssl ecparam -name secp384r1) -keyout certs/tls.key -out certs/tls.crt -days 3650
