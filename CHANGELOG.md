# 1.0.3

## New features

New notion of "special targets" designed to avoid impact on standard target and round time
Iperf2 module is special target
Special targets run after all standard target have been processed
API to create/delete temporary dynamic targets
API is authenticated with token
Slackbot to interact with the API
Option to disable dynamic inventories
Able to choose the source IP of the packets sent

## Breaking changes
nb_packets:
    it is now the number of packets sent per group
    before it was the number of packets per source port for each groups

## Changes

Separate start process from main
Replace host_name by hostname for dynamic_inventories
Default logging level for pykwalify is WARNING
Remove mysql-connector-python version fix
Unit tests improvements
Timeout is not mandatory anymore

## Fixes
UDP send/receive packets mismatch: adding IP id value


# 1.0.2

## New features

UDP unreachable probe added (waiting for ICMP port unreachable response)
New metric to know when reload conf is failing

## Changes

Scapy Monkey patching to make promiscuous mode work
The probe is now in non-promiscuous mode
Log messages improvments
Ignore TCP packets when port mismatches
Improve filtering on ICMP
Permit . and - in target/group name

## Fixes

Crash when matching TCP send/receive fails
APP_PROCESS_TIMED_OUT unexpected argument
UDP dynamic target not in the right list


## Fixes

# 1.0.1

## New features

Set percentile to calculate via configuration file
Support DF bit (default set to true)

## Changes

Improving updating logs
Improve Python2 compatibility: replacing type test by isinstance
Updating Dockerfile: use python image
New logging format
Clean metrics when probe_name is changed
Changing some logs level
Source port range not mandatory anymore in groups
Set default value of "state" for dynamic inventory
Dynamic_inventories/external_links set interval & timeout to real
Changing interval and timeout (for scapy) to float
Building PEX from source in Dockerfile
Code improvements
Fixing scapy to 2.4.0 version in requirements

## Breaking changes
In configuration: force_raw_socket rename to l3_raw_socket

## Fixes

Solve duplicate logs issue
Clean metrics when probe_name is changed
Mismatch s/r TCP packets: metrics and workaround
Set ID and SEQ for ICMP: fixes matching issues when passing firewalls
Don't Fragment was only used in subnet targets
Don't Fragment set to False not working


# 1.0

## New features

Signal handlers
Reload configuration periodically
Logging implementation
Payload generation
Threshold metrics
Probe name
group association/exception for targets
Support of subnet/range/regex
Generic Prometheus metric cleaning
State label for targets
Dynamic inventory loaded automatically and run in processes
ICMP
Rollback if reload fail
DNS resolution update by target
Adding Alert level support

## Changes

Adding logs
Renaming metrics and changing latency to seconds
Adding regex check for Probe/Group name
Adding Dockerfile for dev environment
Calculate real time to wait between rounds
PEP257 compliance
Add default value for DSCP
Some config statement optional
Transform main in Class (first step)
Use unique TCP sequence ID to match response to request more effectively
Description not mandatory anymore
Changing sequence to map in config
Unit tests
Renaming 'Probe' to 'Target' to avoid confusion
Prevent probe from pinging itself
Calculate loss ratio directly
Packets pre-generation for each IP in subnets
Replacing Counter by Gauge for loss ratio
Don't capture traffic from its own server
Do not update DNS if attribute is 0
Adding timeout for processes
Process timeout: metrics and kill if necessary

# 0.9 PoC

TCPsyn probing support
Multiprocessing implementation
Prometheus implementation
Config file support
Interval support
DSCP support
nbPacket support (loop)
dns_update_interval
Sending TCP RST
PEX support
schema_config.yaml
