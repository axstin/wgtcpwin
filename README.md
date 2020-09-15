# wgtcpwin

A convenience script for running WireGuard over TCP (specifically [wstunnel](https://github.com/erebe/wstunnel)) on Windows

## Usage
```
usage: wgtcpwin.py [-h] [--server SERVER] --port PORT
                   [--listen-port LISTEN_PORT] [--wireguard-exe WIREGUARD_EXE]
                   [--safe-activate] [--wstunnel-dest WSTUNNEL_DEST]
                   [--wstunnel-exe WSTUNNEL_EXE]
                   config_path

WireGuard over TCP

positional arguments:
  config_path           the WireGuard config to use

optional arguments:
  -h, --help            show this help message and exit
  --server SERVER, -s SERVER
                        the tunnel server ip. if not provided, it is parsed
                        from the provided config
  --port PORT, -p PORT  the tunnel server port
  --listen-port LISTEN_PORT, -l LISTEN_PORT
                        the tcp tunnel port to listen on and wireguard client
                        should connect to. default 3333
  --wireguard-exe WIREGUARD_EXE
                        location of wireguard.exe. by default, wgtcpwin looks
                        for WireGuard in your PATH or at C:\Program
                        Files\WireGuard\wireguard.exe
  --safe-activate, -d   attempts to deactivate the tunnel, in case it's
                        running, before activating it
  --wstunnel-dest WSTUNNEL_DEST, -r WSTUNNEL_DEST
                        wstunnel: where wstunnel should forward packets on the
                        server. if not provided, the value `127.0.0.1:port` is
                        used where `port` is parsed from the endpoint in the
                        provided config
  --wstunnel-exe WSTUNNEL_EXE
                        wstunnel: location of wstunnel.exe. by default,
                        wgtcpwin looks for wstunnel in your PATH or the
                        current directory
```

`config_path` refers to any valid WireGuard config. wgtcpwin.py will parse it, generate a new config with modified `Endpoint` and `AllowedIPs` fields, start a TCP tunnel (using `wstunnel`), and then activate WireGuard using `wireguard.exe /installtunnelservice new_config`. Pressing enter will deactivate the WireGuard and TCP tunnels.

## Example
Assuming WireGuard has already been installed and configured (on both the client and server):

### Server
> wstunnel -v --server ws://0.0.0.0:443 --r 127.0.0.1:51820

### Client
> py -3 wgtcpwin.py -s SERVER_IP -p 443 -r 127.0.0.1:51820 myconf.conf

where `443` is the port where wstunnel listens (TCP) and `51820` is the port where WireGuard (UDP) listens. `-s` and `-r` options can be omitted and implied from `myconf.conf`'s `Endpoint` field, if valid.