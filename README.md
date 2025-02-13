# vpp-sflow
sFlow plugin for VPP
![vpp-sflow 001](https://github.com/user-attachments/assets/40044f09-4cdc-4e29-9f79-5ba66d2bd124)

# Getting Started
In a directory $SRC (so that $SRC/vpp has the vpp project) you can clone this project and then use a soft link to make the plugin appear as $SRC/vpp/src/plugins/sflow.  After than you can just rebuild VPP. So the steps are...
```
cd $SRC && git clone https://github.com/sflow/vpp-sflow
cd $SRC/vpp/src/plugins && ln -s $SRC/vpp-sflow/sflow
cd $SRC/vpp && make rebuild
```

# Load Kernel Module
It is necesary for the "psample" kernel module to be loaded (both now and on reboot):
```
sudo modprobe psample
sudo sh -c 'echo "psample" > /etc/modules-load.d/sflow.conf'
```

# Logging
You may want your VPP startup.conf file to have an entry like this:
```
logging {
  class sflow/all { rate-limit 10000 level debug syslog-level debug }
}
```

# Example CLI config:
```
vppctl sflow sampling-rate 10000
vppctl sflow polling-interval 20
vppctl sflow enable GigabitEthernet0/8/0
vppctl sflow enable GigabitEthernet0/9/0
vppctl sflow enable GigabitEthernet0/a/0
```

# hsflowd required
To export standard sFlow hsflowd must be running, with its mod_vpp module compiled and enabled. The steps are...
```
cd $SRC && git clone https://github.com/sflow/host-sflow
cd $SRC/host-sflow
make FEATURES=VPP
sudo make install
# Now edit /etc/hsflowd.conf to enable mod_vpp and mod_psample. See example below.
sudo systemctl enable hsflowd
sudo systemctl start hsflowd
```

Example /etc/hsflowd.conf:
```
sflow {
  collector { ip=127.0.0.1 udpport=6343 }
  psample { group=1 egress=on }
  dropmon { start=on limit=50 }
  vpp { }
}

```
You can add multiple collectors. If one is only reachable in another namespace you can use:
```
  collector { ip=172.16.1.1 namespace=mgmt }
```
Or in a VRF represented by a Linux netdev:
```
  collector { ip=192.168.100.2 dev=mgmt0 }
```
For more details on hsflowd.conf features and config, see https://sflow.net/host-sflow-linux-config.php

# Confirm sFlow output
The sflowtool utility can asciify the sFlow feed in various ways. If you have docker you can invoke:
```
docker run sflow/sflowtool
```
OR, to build and run sflowtool from sources the steps are:
```
cd $SRC && git clone https://github.com/sflow/sflowtool
cd $SRC/sflowtool
./boot.sh
./configure
make
sudo make install
sflowtool
```

To start with you may only see counter-samples for each interface and for the host as a whole, but when significant traffic enters the VPP interfaces that were configured for sFlow then you should also see packet-samples printed by sflowtool.

You can adjust the sampling-rate dynamically at any time at the vpp CLI (if you are just running 'ping' then you can set it to 1):
```
sflow sampling-rate 100
```


# Python API

An example that shows how to manipulate the sFlow plugin programmtically in Python:

```python
from vpp_papi import VPPApiClient, VPPApiJSONFiles
import sys

vpp_api_dir = VPPApiJSONFiles.find_api_dir([])
vpp_api_files = VPPApiJSONFiles.find_api_files(api_dir=vpp_api_dir)
vpp = VPPApiClient(apifiles=vpp_api_files, server_address="/run/vpp/api.sock")
vpp.connect("sflow-api-client")
print(vpp.api.show_version())

print(vpp.api.sflow_sampling_rate_set(sampling_N=10000))
print(vpp.api.sflow_sampling_rate_get())
print(vpp.api.sflow_polling_interval_set(polling_S=30))
print(vpp.api.sflow_polling_interval_get())
print(vpp.api.sflow_header_bytes_set(header_B=96))
print(vpp.api.sflow_header_bytes_get())

print(vpp.api.sflow_enable_disable(hw_if_index=1, enable_disable=True))
print(vpp.api.sflow_enable_disable(hw_if_index=2, enable_disable=True))
print(vpp.api.sflow_interface_dump())                 # Both interfaces
print(vpp.api.sflow_interface_dump(hw_if_index=2))    # Single interface
print(vpp.api.sflow_interface_dump(hw_if_index=1234)) # Non-existent

print(vpp.api.sflow_enable_disable(hw_if_index=1, enable_disable=False))
print(vpp.api.sflow_interface_dump())                 # Only interface 2
print(vpp.api.sflow_enable_disable(hw_if_index=2, enable_disable=False))
print(vpp.api.sflow_interface_dump())                 # No interfaces
```
