README
Danielle Zelin

set1.pcap
1) There are 861 packets in set1.pcap.
2) File Transfer Protocol (FTP)
3) The files are not encrypted using FTP, so the data is visible to any who has access to the packet
4) SSH File Transfer Protocol (SFTP)
5) 192.168.1.8
6) Username: defcon
   Password: m1ngisablowhard
7) 6 Files were transfered
8) COaqQWnU8AAwX3K.jpg,
   CDkv69qUsAAq8zN.jpg,
   CNsAEaYUYAARuaj.jpg,
   CLu-m0MWoAAgjkr.jpg,
   CKBXgmOWcAAtc4u.jpg,
   CJoWmoOUkAAAYpx.jpg
9) Files are saved in this directory

set2.pcap
10) There are 77982 packets in set2.pcap.
11) There was 1 username-password pair. However, there were 11 public accounts which were anonymous logins.
12) I used the command dsniff which is a password sniffer and the option -p sniffs passwords for pcap files.
13) 
	Username:    larry@radsot.com
	Password:    Z3lenzmej
	Protocol:    IMAP
	Server IP:   76.0d.78.57.d6.net
	Domain Name: dom.bg
	Port Number: 143

14) I can tell that the username and password for larry@radsot.com are valid because the emails between him and other sources are visible when looking through wireshark. Also, words like OK and 200 were displayed when the TCP stream was followed. For example, it is clear that on Friday August 7, 2015 Larry canceled an amazon order of "Pioneer DDJ-SB Performance...". He received an email for "order-update@amazon.com" that has the subject that he canceled this order. Like this amazon order, there are several other emails that can be viewed.

set3.pcap
15) There were 2 username-password pairs. There were several other public accounts whic were anonymous logins. 
16) 
	Username:    seymour
	Password:    butts
	Protocol:    HTTP
	Server IP:   162.222.171.208
	Domain Name: forum.defcon.org 
	Port Number: 80

	Username:    jeff
	Password:    asdasdasd
	Protocol:    HTTP
	Server IP:   54.191.109.23
	Domain Name: ec2.intelctf.com
	Port Number: 80

17) The username seymour with password butts is not legitimate because the status code given was 403 Forbidden. Also the username jeff with password asdasdasd is not legitimate becuase the status code given was 401 Unauthorized.

18) The lists of all of the IPs and associated domains are stored in ips_and_domains.txt in this directort. I used the command:
	tshark -r set3.pcap -q -z hosts,ipv4 > ips_and_domains.txt	 

19) To verify successful username-password pairs, I checked the TCP streams to look for key words like 200, OK, or 403, and 401. If 200 and OK existed in the stream, then the username-password pairs were verified.

20) I would tell the users to use sites that encrypt their information. Therefore, even though people can get access to the pcaps that store their information, all of it will not mean anything because the username and password will not be directly stored as the string they type in.

