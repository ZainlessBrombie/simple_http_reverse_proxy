# simple_http_reverse_proxy
A simple reverse proxy written in rust that allows for Basic auth for http and https on both ends.

This proxy allows you to set up a reverse http proxy that can filter requests based on Basic auth.
Simpler and faster to configure than an nginx reverse proxy. The http performance is probably way better too, since it is plain hyper framework rust. Outward https performance may not be quite as good, but I'd have to verify that.

## Running the proxy

`PORT=80  PROXY_TARGET=https://github.com  BASIC_AUTH=someuser:somepw  ./http_proxy`
Optionally you may add SSL_PRIVATE_FILE and SSL_SERVER_CERT to run the server in https mode.

