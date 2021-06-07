# Python Netio Discover

Python utility to discover devices on the local network.

Works based on UDP discover documented at [wiki.netio.eu](https://wiki.netio-products.com/index.php?title=NETIO_UDP_Discover)

# Requirements
 - python3.7 + 
 - `netifaces` package

Discover can be used without netifaces package, see section [without netifaces](#without-netifaces)

## Usage:
Discover can be used from the command line as `python3 NetioDiscover.py`
or as a python Class programmatically:

```python
from NetioDiscover import  NetioDiscover

# initialize discover class
nd = NetioDiscover(['eth0', 'enp0s25'])

# find all devices
devices = nd.discover_devices(timeout=3)

# print found devices
for device in devices:
    print(device.get('hostname'), device.get('mac'), device.get('ip'))
```

### without netifaces
You can also use the discovery routine directly, 
thus skipping the interface discovery which is done using netifaces package.

```python
from NetioDiscover import  NetioDiscover

# create interface we'll be discovering devices on
interface = NetioDiscover.Interface(addr='192.168.101.150', broadcast='192.168.101.255')

# discover and print devices
for device in NetioDiscover.find_devices_on_interface(interface):
    print(device)
```
