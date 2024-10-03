# vpp-sflow
sFlow plugin for VPP
![vpp-sflow 001](https://github.com/user-attachments/assets/40044f09-4cdc-4e29-9f79-5ba66d2bd124)
# Getting Started
Assuming a directory $SRC where all sources reside (e.g. /home/USER/src). You can clone this project there, and then use a soft link to make the sflow directory appear as /vpp/src/plugins/sflow.  After than you can just rebuild VPP. So the steps are...
1. cd $SRC && git clone https://github.com/sflow/vpp-sflow
2. cd $SRC/vpp/src/plugins && ln -s $SRC/vpp-sflow/sflow
3. cd $SRC/vpp && make rebuild

Example VPP sFlow config:
```
vppctl sflow sampling-rate 10000
vppctl sflow polling-interval 20
vppctl sflow enable GigabitEthernet0/8/0
vppctl sflow enable GigabitEthernet0/9/0
vppctl sflow enable GigabitEthernet0/a/0
```

# hsflowd required
To export standard sFlow hsflowd must be running, with the mod_vpp module compiled and enabled. The steps are...
1. cd $SRC && git clone https://github.com/sflow/host-sflow
2. cd $SRC/host-sflow && make FEATURES=VPP build install
3. edit /etc/hsflowd.conf to enable mod_vpp by adding the line "vpp {}".  This is also where you set the collector IP.
5. sudo systemctl enable hsflowd && sudo systemctl start hsflowd

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
The sflowtool utility can asciify the sFlow feed in various ways. The steps are...
1. cd $SRC && git clone https://github.com/sflow/sflowtool
2. cd $SRC/sflowtool && ./boot.sh && ./configure && make && sudo make install
3. sflowtool (or sflowtool -l, or sflowtool -J, or...)

Now you are ready to introduce significant traffic to the VPP interfaces, and (hopefully) confirm that samples appear without impacting VPP forwarding performance.
