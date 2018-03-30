# dc402-client-probe-dash

## Requirements
```
pip install -r requirements.txt
```
manually install https://github.com/coolbho3k/manuf

scapy has it's own dependencies, for instance libpcap-devel or libpcap-dev depending on your distribution.
if you have issues, see http://scapy.readthedocs.io/en/latest/installation.html#platform-specific-instructions

## In Use
Use airmon-ng (part of aircrack-ng) to get wifi adapter into monitor mode, and then pass the monitor interface to script as 
commandline arg, like so:

```
airmon-ng start wlan0
python clientprobe.py wlan0mon
```

when done, you likely want to return the interface to non-monitor mode:

```
airmon-ng stop wlan0
```

## Credit
OUI and dBm parsing borrowed from: https://github.com/nikharris0/probemon/blob/master/probemon.py
