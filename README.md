## What it does?

It publishes mdns records for local services, and serves them using caddy with https.

## Requirements:

- `dns-sd` binary (so this **runs only on mac**)
- `caddy` - https://caddyserver.com/

## Example usage:

```sh
go run github.com/DeluxeOwl/localhttps@latest -ip 192.168.0.23 -config .localhttps.yaml
```

## How it works

This is a go binary that does the following:

1. Goes over the config file (default `.localhttps.yaml`) and reads domain/address pairs (address is in the format `ip:port`)  
   Example file

```yaml
frontend.local: "127.0.0.1:5173"
backend.local: "127.0.0.1:8080"
```

2. Creates a `Caddyfile`

```
frontend.local {
    tls internal
    reverse_proxy 127.0.0.1:5173
}

backend.local {
    tls internal
    reverse_proxy 127.0.0.1:8080
}
```

3. Runs `caddy` with the generated `Caddyfile`
4. Runs `dns-sd -P <domain> _http._tcp local 443 <domain> <ip>`
