# ArcaneTrickster
ArcaneTrickster, or "Arcane," is an event-driven research library for low-level networking. It was built as a research tool for TunnelVision (CVE-2024-3661) because we lacked a robust, rogue DHCP server.

Its goals are to:
* Take over as the de-facto DHCP server without relying on race conditions
* Minimize disruption to clients
* Provide flexibility for diverse environments

## Install
```python3
git clone https://github.com/superit23/arcanetrickster.git
python3 -m venv arcaneenv
source ./arcanenev/bin/activate
python3 -m pip install r ./arcanetrickster/requirements.txt
```

## Usage
Currently, Arcane requires some amount of programming skill to use. However, we built an easy TunnelVision PoC in the "tunnelvision.py" script that executes the adjacent host decloaking attack.

Here's an example. Imagine we're on the 10.10.10.0/24 subnet, 10.10.10.1 is the authoritative DHCP server, our current IP is 10.10.10.220, and we want to snoop on traffic to 8.8.8.8. We'd listen on the appropriate interface with `-i`, tell the DHCPReleaser to send releases to 10.10.10.1 with `-s`, and inject a route for 8.8.8.8 to 10.10.10.220 with `-r`.
```python3
python3 ./tunnelvision.py -i enp0s3 -s 10.10.10.1 -r 8.8.8.8/32:10.10.10.220
```
