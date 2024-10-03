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
It is necesary for the "psample" kernel module to be loaded:
```
sudo modprobe psample
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
For more details on hsflowd.conf features and config, see https://sflow.net/host-sflow-linux-config.php

# Confirm sFlow output
The sflowtool utility can asciify the sFlow feed in various ways. The build steps are...
```
cd $SRC && git clone https://github.com/sflow/sflowtool
cd $SRC/sflowtool
./boot.sh
./configure
make
sudo make install
sflowtool
```

When significant traffic enters the VPP interfaces that were configured for sFlow, you should see packet-samples printed by sflowtool.

You can adjust the sampling-rate dynamically at any time at the vpp CLI:
```
sflow sampling-rate 500
```


