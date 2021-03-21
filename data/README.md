# Data

The files are filtered from the following public traces:
* DHCP, ICMP, NTP, SMB, SMB2
    - SMIA 2011: [https://download.netresec.com/pcap/smia-2011/](https://download.netresec.com/pcap/smia-2011/)  
    [NEMESYS](https://github.com/vs-uulm/nemesys/) also provides some traces filtered from SMIA
    - DHCP: `bootp`
    - ICMP: `icmp`
    - NTP: `ntp`
    - SMB: `smb`
    - SMB2: `smb2 && !nbss.continuation_data`

* DNP3
    - DCA: [https://github.com/igbe/DNP3-Dataset-Plus-SnortRules](https://github.com/igbe/DNP3-Dataset-Plus-SnortRules)

* Modbus
    - ICS: [https://github.com/ITI/ICS-Security-Tools/blob/master/pcaps/bro/modbus/modbus.pcap](https://github.com/ITI/ICS-Security-Tools/blob/master/pcaps/bro/modbus/modbus.pcap)
    - other: [https://www.cloudshark.org/captures/3bfef9452c76?filter=modbus](https://www.cloudshark.org/captures/3bfef9452c76?filter=modbus)(some messages contain more than one mbtcp)

* TFTP
    - tftp-dup: [https://www.cloudshark.org/captures/07ebe14c792b](https://www.cloudshark.org/captures/07ebe14c792b)

* ZeroAccess
    - ISCX_Botnet-Testing: [https://www.unb.ca/cic/datasets/botnet.html](https://www.unb.ca/cic/datasets/botnet.html)
    - `!rtcp && !dns`

Other public traces:
* NETRESEC: [https://www.netresec.com/?page=PcapFiles](https://www.netresec.com/?page=PcapFiles)
