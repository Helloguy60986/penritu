# nettools (GitHub-ready)

## setup.py

from setuptools import setup, find_packages

setup(
    name='nettools',
    version='0.1.0',
    description='Safe network helper CLI (passive site info + ping wrapper)',
    packages=find_packages(),
    include_package_data=True,
    install_requires=['requests'],
    entry_points={
        'console_scripts': [
            'pentest=nettools.cli:pentest_cmd',
            'pingip=nettools.cli:pingip_cmd',
        ],
    },
    python_requires='>=3.8',
)

## nettools/cli.py

#!/usr/bin/env python3
import argparse
import platform
import subprocess
import sys
import socket
import ssl
from urllib.parse import urlparse

import requests


def safe_print(*args, **kwargs):
    print(*args, **kwargs)


def ping_ip(target: str, count: int = 4):
    system = platform.system().lower()
    if system == 'windows':
        cmd = ['ping', '-n', str(count), target]
    else:
        cmd = ['ping', '-c', str(count), target]

    safe_print(f"Running: {' '.join(cmd)}")
    try:
        completed = subprocess.run(cmd, check=False, text=True, capture_output=True)
        safe_print(completed.stdout)
        if completed.returncode != 0:
            safe_print('Ping finished with non-zero exit code:', completed.returncode)
    except FileNotFoundError:
        safe_print("'ping' command not found on this system.")


def fetch_http_info(url: str, timeout: int = 8):
    parsed = urlparse(url)
    if not parsed.scheme:
        url = 'http://' + url
    try:
        r = requests.get(url, timeout=timeout, allow_redirects=True)
        info = {
            'final_url': r.url,
            'status_code': r.status_code,
            'headers': dict(r.headers),
        }
        return info
    except Exception as e:
        return {'error': str(e)}


def fetch_robots_txt(url: str, timeout: int = 5):
    parsed = urlparse(url)
    host = parsed.netloc or parsed.path
    robots_url = f"{parsed.scheme or 'http'}://{host}/robots.txt"
    try:
        r = requests.get(robots_url, timeout=timeout)
        return {'url': robots_url, 'status_code': r.status_code, 'contents': r.text[:2000]}
    except Exception as e:
        return {'error': str(e)}


def fetch_tls_cert(host: str, port: int = 443, timeout: int = 5):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                return {'cert': cert}
    except Exception as e:
        return {'error': str(e)}


def resolve_dns(host: str):
    try:
        ips = socket.gethostbyname_ex(host)[2]
        return {'ips': ips}
    except Exception as e:
        return {'error': str(e)}


def is_likely_local(host: str):
    try:
        ip = socket.gethostbyname(host)
    except Exception:
        return False
    private_prefixes = ('10.', '172.', '192.168.', '127.')
    return ip.startswith(private_prefixes)


def pentest_cmd(argv=None):
    parser = argparse.ArgumentParser(prog='pentest', description='Safe, passive recon info for a target (non-invasive)')
    parser.add_argument('target', help='Target hostname or URL (e.g. example.com or https://example.com)')
    parser.add_argument('--allow-remote', action='store_true', help='I confirm I have authorization to test remote (non-local) targets')
    args = parser.parse_args(argv)

    parsed = urlparse(args.target)
    hostname = parsed.netloc or parsed.path

    if not args.allow_remote and not is_likely_local(hostname):
        safe_print('
=== SAFETY BLOCK ===')
        safe_print('It looks like the target is not local/private. To avoid misuse, this tool will only run passive checks on local/private targets by default.')
        safe_print('If you own this target or have written authorization, re-run with --allow-remote to proceed.')
        safe_print('Alternatively, to run active scans (e.g. nmap), run those tools locally yourself on authorized systems.')
        return

    safe_print(f"Performing passive recon on: {hostname}
")

    safe_print('1) DNS resolution:')
    dns = resolve_dns(hostname)
    safe_print(dns)

    safe_print('
2) HTTP info (status & headers):')
    http = fetch_http_info(args.target)
    safe_print(http)

    safe_print('
3) robots.txt (first 2000 chars):')
    robots = fetch_robots_txt(args.target)
    safe_print(robots)

    safe_print('
4) TLS certificate info (if available):')
    tls = fetch_tls_cert(hostname)
    safe_print(tls)

    safe_print('
Passive recon complete. For active port/service scanning use nmap on systems you are authorized to test.')


def pingip_cmd(argv=None):
    parser = argparse.ArgumentParser(prog='pingip', description='Ping an IP or hostname using system ping')
    parser.add_argument('target', help='IP or hostname to ping')
    parser.add_argument('-c', '--count', type=int, default=4, help='Number of echo requests')
    args = parser.parse_args(argv)
    ping_ip(args.target, args.count)


if __name__ == '__main__':
    if len(sys.argv) >= 2 and sys.argv[1] == 'pingip':
        pingip_cmd(sys.argv[2:])
    else:
        pentest_cmd(sys.argv[1:])

## nettools/__init__.py

__version__ = '0.1.0'

## README.md

A small, safe network helper CLI. This project provides two console commands after installation:

- `pentest` — passive, non-invasive reconnaissance (DNS, HTTP headers, robots.txt, TLS cert)
- `pingip` — simple wrapper around the system `ping` command

Safety first: This tool intentionally avoids active scanning (no port scans, no vulnerability exploitation).
Only run network tests against systems you own or have explicit written authorization for.

Install (locally):

```
python -m pip install --upgrade pip
pip install .
```

Examples:

```
pentest localhost
```

```
pingip 8.8.8.8 -c 3
```

If you need active scans, run nmap manually on machines you control.

License: MIT recommended for examples.
