.. _Sflow_agent:

.. toctree::

SFlow Monitoring Agent
======================

Overview
________

This plugin implements the random packet-sampling and interface
telemetry streaming required to support standard sFlow export
on Linux platforms. The overhead incurred by this monitoring is
minimal, so that detailed, real-time traffic analysis can be
achieved even under high load conditions, with visibility into
any fields that appear in the packet headers. If the VPP linux-cp
plugin is running then interfaces will be mapped to their
equivalent Linux tap ports.

Example Configuration
_____________________

sflow sampling-rate 10000
sflow polling-interval 20
sflow header-bytes 128
sflow enable GigabitEthernet0/8/0
sflow enable GigabitEthernet0/9/0
sflow enable GigabitEthernet0/a/0

External Dependencies
_____________________

This plugin writes packet samples to the standard Linux
netlink PSAMPLE channel, and shares periodic interface counter
samples vi netlink USERSOCK.  The host-sflow daemon, hsflowd, at
https://sflow.net is one example of a tool that will consume
this feed and emit standard sFlow v5.
