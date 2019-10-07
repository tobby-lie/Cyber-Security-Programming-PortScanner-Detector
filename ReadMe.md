# PortScanner Detector

Builds port scanner based on previous labs completed in course.

## Description

"RBS detector measures the rate of connections to new destinations. It works based on the hyptothesis that a
scanning host contacts new destinations (IP+port) at a higher rate than a legitimate one does."

Jung, Jaeyon, Rodolfo A. Milito, and Vern Paxson. "On the adaptive real-time detection of fast-propagating network
worms." International Conference on Detection of Intrusions and Malware, and Vulnerability Assessment. Springer,
Berlin, Heidelberg, 2007. [Link](https://link.springer.com/content/pdf/10.1007%2Fs11416-007-0080-y.pdf)

Inspired by the above methodology, I was to use what was learned in previous labs in order to build a tool that
detects port scanners. 

The tool ran on Kali Linux VM tested against a clone of itself that ran a port scanner.

## Part 1 - PortScanner Detector

Program will be multi-threaded.

One thread will sniff traffic, for every connection from <srcIP, srcPort> to <dstIP, dstPort>, it records
<(srcIP, dstIP, dstPort), timestamp> in a table which is refered to a first-contact connection request. Every
first-contact connection is stored for 5 minutes before being deleted. If (src, dstIP, dstPrt already exists
then do nothing. As a result of this, a dict in Python3 was utilized. 

Another thread was utilized to disposeof all connections older than 5 minutes.

Another thread calculated fan-out rates of each source IP. Fan out rate is the rate of establishing new connections
per time interval. For example, fan out rate of 5/s peans the source host has made 5 first-contact connections in
the last second. The fan out rate was calculated for three intervals: per second, per minute and per 5 minutes. If
the fanout rate per sec exceeds 5, per min exceeds 100 and per 5 min exceeds 300 then the source IP is detected as
a port scanner. 

### Example Output:
```
portscanner detected on source IP x
avg. fan-out per sec: y, avg fan-out per min: z, fan-out per 5min: d

reason: fan-out per sec = 6 (must be less than 5)
```

## Part 2 - PortScanner

Utilize portscanner from previous lab in order to perform TCP port-scan. The portscanner will be updated to receive
a waiting time in milliseconds between every two scans to different destinations (IP+port). It will respect the 
waiting time between every two consecutive scans. 

## Part 3 - Test

For testing, this was done in two Kali Linux VMs, one to portscan detect and the other to port scan. They were 
ensured to belong to the same LAN 192.168.10.*/24. It was tested against 5 different waiting times: 1ms, 0,5s, 1s,
5s, 10s
