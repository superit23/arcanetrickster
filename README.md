# ArcaneTrickster
ArcaneTrickster, or "Arcane," is an event-driven research library for low-level networking. It was built as a research tool for TunnelVision (CVE-2024-3661) because we lacked a robust, rogue DHCP server.

It's goals are to:
* Take over as the de-facto DHCP server without relying on race conditions
* Minimize disruption to clients
* Provide flexibility for diverse environments

## Usage
Currently, Arcane requires some amount of programming skill to use. The "arcane.py" file in the root directory is a good starting point for running an adjacent host decloaking attack.

First, create a virtual environment and install the dependencies.
```python3
python3 -m venv arcaneenv
source ./arcanenev/bin/activate
python3 -m pip install r ./arcanetrickster/requirements.txt
```

Then modify and run "arcane.py".
```python3
python3 ./arcane.py
```
