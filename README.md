# NginS

NginS is a modern SNI Proxy that forwards web requests to a SOCKS5 server. It acts as an HTTP/HTTPS reverse proxy, facilitating traffic routing through a SOCKS5 tunnel instead of direct web server forwarding.

## Requirements

1. A SOCKS5 Server.
2. A DNS Server (e.g., AdGuardHome).
3. NginS Binary.

## Usage

1. **Configure SOCKS5**: Ensure your SOCKS5 server is reachable.
2. **Configure NginS**: Edit `config.yml` or create a custom one.
3. **Run NginS**:
   - Using default config: `./ngins`
   - Using custom config: `./ngins -C mycfg` (loads `mycfg.yml`)
4. **DNS Setup**: Point the `A` or `AAAA` records of target domains to the NginS server IP.
5. **DNS Forwarding**: Ensure all other domains resolve through a public DNS (e.g., 8.8.8.8) to maintain connectivity.
6. **Network Settings**: Set the local DNS server as your primary DNS.

## Configuration

The `config.yml` file contains two main sections:

- **server**: Listening configuration for the proxy.
  - `httpHost`: "0.0.0.0"
  - `httpPort`: "80"
  - `httpsHost`: "0.0.0.0"
  - `httpsPort`: "443"
- **proxy**: Backend SOCKS5 configuration.
  - `socks5Host`: "127.0.0.1"
  - `socks5Port`: "1080"
