# Promgate

Promgate is a pure go-stdlib mutal tls reverse proxy to merge multiple prometheus exporters together.

All exporters are are queried in parallel and appendend line wise. The goal is to transmit the metrics, not to keep the help texts.

It's configured entirely using environment variables. You may scream for flags, but i happen like Systemd's environment files.

Usage:

```
CA=ca.pem \
CRL=crl.pem \
CERT=cert.pem \
KEY=key.pem \
URLS=http://localhost:9100/metrics,http://localhost:9101 \
go run promgate.go
```

**Note**: you have to supply all of these options.

`URLS` is a single URL or a list of comma sperated urls. The scheme (i.e. http://) is required.
