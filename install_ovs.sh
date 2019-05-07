#!/bin/bash

ovs-vsctl del-br br0
sleep 10s
ovs-vsctl add-br br0
ovs-vsctl add-port br0 enp0s3
ifconfig enp0s3 0
dhclient br0
ovs-vsctl set bridge br0 protocols=OpenFlow10,OpenFlow13
