# Spike summaries

## s02-screenconnect-backdoor  (Low, 7 alerts, 9.8s)

**Facts given to the model**

```
Number of alerts: 7
First alert: 16:43 UTC on Sep 14, 2026
Last alert: 16:43 UTC on Sep 14, 2026
Home network device(s) involved: 10.9.14.101, 10.9.14.1
Outside address(es) involved: 184.194.97.23
Outside port(s): 443
Alert names (from Suricata): ET REMOTE_ACCESS Observed DNS Query to Known ScreenConnect/ConnectWise Remote Desktop Service Domain (2x); ET REMOTE_ACCESS Remote Monitoring and Management (RMM) Tool in DNS Lookup (screenconnect .com) (2x); ET REMOTE_ACCESS Remote Monitoring and Management (RMM) Tool in DNS Lookup (check .screenconnect .com) (1x); ET REMOTE_ACCESS Observed Remote Monitoring and Management (RMM) Tool in TLS SNI (screenconnect .com) (1x); ET REMOTE_ACCESS Observed Remote Monitoring and Management (RMM) Tool in TLS SNI (check .screenconnect .com) (1x)
Severity: Low
```

**Model output**

There were 7 alerts on your home network. The device 10.9.14.101 tried to connect to an outside address 184.194.97.23 using port 443. The alerts show it was looking for domains related to remote monitoring tools. The severity is Low. You should check if any unknown devices are connected to your network.

**Indicator check:** pass  
**Flesch-Kincaid grade:** 3.8

## s03-xworm  (Medium, 1 alerts, 3.9s)

**Facts given to the model**

```
Number of alerts: 1
First alert: 18:47 UTC on Sep 8, 2026
Last alert: 18:47 UTC on Sep 8, 2026
Home network device(s) involved: 10.9.8.128
Outside address(es) involved: 43.228.157.141
Outside port(s): 7007
Alert names (from Suricata): ET DROP Spamhaus DROP Listed Traffic Inbound group 5 (1x)
Severity: Medium
```

**Model output**

A medium severity alert was triggered on your home network. The device 10.9.8.128 tried to connect to an outside address 43.228.157.141 on port 7007. This connection is flagged as spam or malicious traffic. You should check if this device is trusted and update your firewall rules if needed.

**Indicator check:** pass  
**Flesch-Kincaid grade:** 4.1

## s04-lumma-stealer  (High, 18 alerts, 4.5s)

**Facts given to the model**

```
Number of alerts: 18
First alert: 19:18 UTC on Aug 10, 2026
Last alert: 19:24 UTC on Aug 10, 2026
Home network device(s) involved: 172.16.1.101, 172.16.1.1
Outside address(es) involved: 31.216.144.5
Outside port(s): 443
Alert names (from Suricata): ET MALWARE Win32/Lumma Stealer Related CnC Domain in DNS Lookup (futupath .cyou) (9x); ET FILE_SHARING Observed DNS Query to Filesharing Service (mega .co .nz) (5x); ET FILE_SHARING File Sharing Related Domain in DNS Lookup (mega .nz) (2x); ET FILE_SHARING File Sharing Domain Observed in TLS SNI (mega .nz) (2x)
Severity: High
```

**Model output**

Your home network had a high-severity security issue. The device 172.16.1.101 tried to connect to a bad website called futupath.cyou. It also looked up other websites like mega.co.nz and mega.nz, which are used for file sharing. These actions happened while your network was talking to an outside address 31.216.144.5 on port 443. You should check your router settings and update your firewall rules to block these suspicious connections.

**Indicator check:** pass  
**Flesch-Kincaid grade:** 5.1

## s05-remcos-rat  (High, 17 alerts, 3.9s)

**Facts given to the model**

```
Number of alerts: 17
First alert: 22:01 UTC on Aug 5, 2026
Last alert: 22:32 UTC on Aug 5, 2026
Home network device(s) involved: 10.8.6.101
Outside address(es) involved: 185.14.92.102
Outside port(s): 443
Alert names (from Suricata): ET MALWARE Remcos 3.x Unencrypted Server Response (16x); ET MALWARE Remcos 3.x Unencrypted Checkin (1x)
Severity: High
```

**Model output**

A high severity alert was triggered 17 times on your home network. The device 10.8.6.101 talked to the outside address 185.14.92.102 on port 443. The alerts are about suspicious activity related to malware called Remcos. You should check if your device was infected and run a security scan.

**Indicator check:** pass  
**Flesch-Kincaid grade:** 5.2

## s06-xloader-formbook  (Medium, 70 alerts, 3.6s)

**Facts given to the model**

```
Number of alerts: 70
First alert: 15:09 UTC on Apr 13, 2026
Last alert: 15:28 UTC on Apr 13, 2026
Home network device(s) involved: 10.4.13.101, 10.4.13.1
Outside address(es) involved: 66.29.152.174, 104.21.62.145, 172.67.211.213, 8.217.99.246
Outside port(s): 80
Alert names (from Suricata): SURICATA HTTP Response excessive header repetition (44x); ET INFO HTTP Request to Suspicious *.life Domain (21x); SURICATA STREAM excessive retransmissions (2x); SURICATA HTTP Unexpected Request body (2x); ET INFO Observed DNS Query to .life TLD (1x)
Severity: Medium
```

**Model output**

There were 70 alerts on your home network. The device 10.4.13.101 talked to several outside addresses. It sent HTTP requests to suspicious domains and had issues with headers and retransmissions. The severity is Medium. Check the settings on your router and update your firewall rules.

**Indicator check:** pass  
**Flesch-Kincaid grade:** 5.0

## s07-guloader-agenttesla  (High, 5 alerts, 4.2s)

**Facts given to the model**

```
Number of alerts: 5
First alert: 11:13 UTC on Feb 3, 2026
Last alert: 11:14 UTC on Feb 3, 2026
Home network device(s) involved: 10.2.3.101, 10.2.3.1
Outside address(es) involved: 208.95.112.1, 162.241.123.75
Outside port(s): 80, 47037, 21
Alert names (from Suricata): ET INFO External IP Lookup Domain in DNS Lookup (ip-api .com) (1x); ET MALWARE Common Stealer Behavior - Source IP Associated with Hosting Provider Check via ip.api .com (1x); ET INFO External IP Lookup ip-api.com (1x); ET MALWARE Agent Tesla CnC Exfil via TCP (1x); ET MALWARE AgentTesla Exfil via FTP (1x)
Severity: High
```

**Model output**

Your home network had a high-severity security issue. The device 10.2.3.101 talked to external IP addresses 208.95.112.1 and 162.241.123.75. These connections involved suspicious activity like checking IP information and sending data, which is linked to malware. You should check your router settings and update your firewall rules to block these IP addresses.

**Indicator check:** pass  
**Flesch-Kincaid grade:** 6.7

## s08-kongtuke-mintsloader  (High, 32 alerts, 4.1s)

**Facts given to the model**

```
Number of alerts: 32
First alert: 12:49 UTC on Feb 2, 2026
Last alert: 12:51 UTC on Feb 2, 2026
Home network device(s) involved: 10.2.2.37, 10.2.2.1
Outside address(es) involved: 64.52.80.153, 85.137.253.64, 34.117.59.81, 216.245.184.175
Outside port(s): 80, 3456, 443, 25658
Alert names (from Suricata): ET INFO Windows Powershell User-Agent Usage (4x); ET INFO Observed WindowsPowerShell/5.1 User Agent Usage (4x); ET INFO External IP Lookup Domain (ipify .org) in DNS Lookup (3x); ET INFO External IP Lookup ipinfo.io (3x); ET EXPLOIT_KIT LandUpdate808 Domain in DNS Lookup (soulversr .com) (2x)
Severity: High
```

**Model output**

There were 32 alerts from your home network device 10.2.2.37 and 10.2.2.1. These devices talked to several outside addresses, including 64.52.80.153 and others. The alerts show unusual activity like checking external IP addresses and possible exploit attempts. The severity is High. You should check your router settings and update your firewall rules.

**Indicator check:** pass  
**Flesch-Kincaid grade:** 6.2

## s09-phantomstealer  (High, 4 alerts, 4.5s)

**Facts given to the model**

```
Number of alerts: 4
First alert: 15:21 UTC on Jan 30, 2026
Last alert: 15:21 UTC on Jan 30, 2026
Home network device(s) involved: 10.1.30.101, 10.1.30.1
Outside address(es) involved: 185.27.134.154, 104.16.185.241
Outside port(s): 80
Alert names (from Suricata): ET INFO Observed UA-CPU Header (1x); ET INFO External IP Lookup Domain in DNS Lookup (icanhazip .com) (1x); ET INFO IP Check Domain (icanhazip. com in HTTP Host) (1x); ET MALWARE Reverse Base64 Encoded MZ Header Payload Inbound (1x)
Severity: High
```

**Model output**

Your home network had four security alerts on January 30, 2026. The device 10.1.30.101 tried to connect to websites using IP addresses 185.27.134.154 and 104.16.185.241 on port 80. These alerts showed unusual activity, including checking for external IP addresses and possible malware signs. The severity is High. You should check your router settings and update your firewall rules.

**Indicator check:** pass  
**Flesch-Kincaid grade:** 6.1

## s10-njrat-masslogger  (High, 16 alerts, 4.3s)

**Facts given to the model**

```
Number of alerts: 16
First alert: 22:03 UTC on Jan 28, 2026
Last alert: 22:05 UTC on Jan 28, 2026
Home network device(s) involved: 10.1.29.101, 10.1.29.1
Outside address(es) involved: 193.122.130.0, 104.248.130.195, 149.154.166.110, 104.21.67.152
Outside port(s): 80, 443, 7492
Alert names (from Suricata): ET INFO External IP Lookup - checkip.dyndns.org (3x); ET INFO External IP Lookup Domain in DNS Lookup (ip-api .com) (1x); ET MALWARE Generic njRAT/Bladabindi CnC Activity (ll) (1x); ET INFO External IP Lookup ip-api.com (1x); ET DYN_DNS External IP Lookup Domain in DNS Query (checkip .dyndns .org) (1x)
Severity: High
```

**Model output**

There were 16 alerts from your home network device 10.1.29.101 and 10.1.29.1. These devices talked to several outside addresses, including 193.122.130.0 and others. The alerts included possible malware activity and checks for external IP addresses. The severity is High. Check if any devices on your network are acting strangely or if you suspect unauthorized access.

**Indicator check:** pass  
**Flesch-Kincaid grade:** 6.4

## spare-vip-recovery  (High, 21 alerts, 4.1s)

**Facts given to the model**

```
Number of alerts: 21
First alert: 23:47 UTC on Jan 19, 2026
Last alert: 23:47 UTC on Jan 19, 2026
Home network device(s) involved: 10.1.14.131, 10.1.14.2
Outside address(es) involved: 193.122.6.168, 149.154.166.110, 104.21.67.152, 91.92.243.152
Outside port(s): 80, 443
Alert names (from Suricata): ET INFO External IP Lookup - checkip.dyndns.org (10x); ET DYN_DNS External IP Lookup Domain in DNS Query (checkip .dyndns .org) (1x); ET HUNTING Telegram API Domain in DNS Lookup (1x); ET INFO Observed Telegram Domain in DNS Lookup (telegram .org) (1x); ET INFO External IP Address Lookup Domain in DNS Lookup (reallyfreegeoip .org) (1x)
Severity: High
```

**Model output**

There were 21 alerts on your home network. The devices 10.1.14.131 and 10.1.14.2 tried to connect to several outside addresses. These connections were related to checking IP addresses and domains used by services like Telegram and free IP lookup tools. The severity is High. You should check your router settings and update your firewall rules to block these suspicious connections.

**Indicator check:** pass  
**Flesch-Kincaid grade:** 5.5
