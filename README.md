# simple_http_reverse_proxy
A simple reverse proxy written in rust that allows for Basic auth

This proxy allows you to set up a reverse http proxy that can filter requests based on Basic auth.
Simpler and faster to configure than an nginx reverse proxy. The performance is probably way better too, since it is plain hyper framework rust.

## Running the proxy

`PORT=80  PROXY_TARGET=https://github.com  BASIC_AUTH=someuser:somepw  ./http_proxy`

## Future enhancement
Support for ssl certificates is intended
