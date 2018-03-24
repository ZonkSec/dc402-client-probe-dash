# dc402-client-probe-dash

## Requirements
```
pip install -r requirements.txt
```

## In Use
Use airmon-ng to get wifi adapater into monitor mode, and then pass the monitor interface to script as 
commandline arg, like so:

```
python clientprobe.py wlan0mon
```
