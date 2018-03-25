# dc402-client-probe-dash

## Requirements
```
pip install -r requirements.txt
```
manually install https://github.com/coolbho3k/manuf

## In Use
Use airmon-ng to get wifi adapater into monitor mode, and then pass the monitor interface to script as 
commandline arg, like so:

```
airmon-ng start wlan0
python clientprobe.py wlan0mon
```

## Credit
OUI and dBm parsing borrowed from: https://github.com/nikharris0/probemon/blob/master/probemon.py
