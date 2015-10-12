require 'packetfu'

# returns true if all of the flags are equal to zero
def isNullScan(packet)
	return (packet.tcp_flags.urg == 0 and packet.tcp_flags.ack == 0 and packet.tcp_flags.psh == 0 and packet.tcp_flags.rst == 0 and packet.tcp_flags.syn == 0 and packet.tcp_flags.fin == 0)
end

# returns true if only the fin flag is set to one
def isFinScan(packet)
	return (packet.tcp_flags.urg == 0 and packet.tcp_flags.ack == 0 and packet.tcp_flags.psh == 0 and packet.tcp_flags.rst == 0 and packet.tcp_flags.syn == 0 and packet.tcp_flags.fin == 1)
		isFIN = true
end

# returns true if the urg, psh, and fin flags are set to one
def isXmasScan(packet)
	return (packet.tcp_flags.urg == 1 and packet.tcp_flags.ack == 0 and packet.tcp_flags.psh == 1 and packet.tcp_flags.rst == 0 and packet.tcp_flags.syn == 0 and packet.tcp_flags.fin = 1)
end

# Only used when live packets are being analyzed
# returns true if the binary version of the word Nmap is found
def isLiveNmap(packet)
	return (packet =~ (/\x4E\x6D\x61\x70/))
end

# Only used when analyzing the plaintext web server file
# returns true if the word Nmap is found
def isServerNmap(packet)
	return (packet.match(/Nmap/i) != nil)
end

# Only used when live packets are being analyzed
# returns true if the binary version of the word Nikto is found
def isLiveNikto(packet)
	return (packet =~ (/\x4E\x69\x6b\x74\x6F/))
end

# Only used when analyzed the plaintext web server file
# returns true if the word Nikto is found
def isServerNikto(packet)
	return (packet.match(/Nikto/i) != nil)
end

# Checks if any format of a credit card is found and returns true if so
def isCreditCard(packet)
	# visa credit card format
	if packet.match(/^4[0-9]{12}(?:[0-9]{3})?$/) != nil
		return true
	# mastercard credit card format
	elsif packet.match(/5\d{3}(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}/) != nil
		return true
	# american express credit card format
	elsif packet.match(/3\d{3}(\s|-)?\d{6}(\s|-)?\d{5}/) != nil
		return true
	# discover credit card format
	elsif packet.match(/6011(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}/) != nil
		return true
	end

	return false
end

# Returns true if the word masscan is found
def isRGMasscan(log)
	return (log.match(/masscan/i) != nil)
end

# Returns true if the character below are found that order 
def isShellshock(log)
	return (log.match(/() { :; }/) != nil)
end

# Returns true if the string phpMyAdmin is found 
def isPHPAdmin(log)
	return (log.match(/phpMyAdmin/i) != nil)
end

# Returns true if the \x is found
def isShellcode(log)
	return (log.match(/\\x/) != nil)
end

# Prints the alerts for both live packets and web server logs
def printAlert(count, incident, sourceIP, protocol, payload, notScan=false)
	if notScan
		puts "#{count}. ALERT: #{incident} in the clear from #{sourceIP} (#{protocol}) (#{payload})"
	else
		puts "#{count}. ALERT: #{incident} is detected from #{sourceIP} (#{protocol}) (#{payload})"
	end
end

# Gets necessary variables for the web server logs
def printLogs(count, incident, log)
	#splitLogs = log.split
	splitLogs = log.split(/\s(?=(?:[^"]|"[^"]*")*$)/)
	sourceIP = splitLogs[0]
	payload = splitLogs[5]
	protocol = 'UDP'
	if log.match(/HTTP/)
		protocol = 'HTTP'
	end
	printAlert(count, incident, sourceIP, protocol, payload)

end

# Reads in the live packets and calls necessary functions to determine if an attack
# is being performed
def analyzeLivePackets()
	count = 0
	cap = PacketFu::Capture.new(:start => true, :iface => 'eth0', :promisc => true)
	cap.stream.each do |p|
		pkt = PacketFu::Packet.parse(p)
		if pkt.is_ip? and pkt.is_tcp?
			if isNullScan(pkt)
				printAlert(count+=1, "NULL scan", pkt.ip_saddr, pkt.proto.last, pkt.payload)
			elsif isFinScan(pkt)
				printAlert(count+=1, "FIN scan", pkt.ip_saddr, pkt.proto.last, pkt.payload)
			elsif isXmasScan(pkt)
				printAlert(count+=1, "XMAS scan", pkt.ip_saddr, pkt.proto.last, pkt.payload)
			elsif isLiveNmap(pkt.payload)
				printAlert(count+=1, "NMAP scan", pkt.ip_saddr, pkt.proto.last, pkt.payload)
			elsif isLiveNikto(pkt.payload)
				printAlert(count+=1, "NIKTO scan", pkt.ip_saddr, pkt.proto.last, pkt.payload)
			elsif isCreditCard(pkt.payload)
				printAlert(count+=1, "Credit card leaked", pkt.ip_saddr, pkt.proto.last, pkt.payload, true)
			end
		end
	end
end		

# Reads in a pcap and calls necessary functions to determine if attacks have been performed
def analyzeReadPackets(pcap)
	pkt = Pcap.open_offline(pcap)
	pkt = PacketFu::PcapFile.read(pcap)
	count = 0
	pkt.each do |p|
		pkt = PacketFu::Packet.parse(p)
		if pkt.is_ip? and pkt.is_tcp?
			if isNullScan(pkt)
				printAlert(count+=1, "NULL scan", pkt.ip_saddr, pkt.proto.last, pkt.payload)
			elsif isFinScan(pkt)
				printAlert(count+=1, "FIN scan", pkt.ip_saddr, pkt.proto.last, pkt.payload)
			elsif isXmasScan(pkt)
				printAlert(count+=1, "XMAS scan", pkt.ip_saddr, pkt.proto.last, pkt.payload)
			elsif isLiveNmap(pkt.payload)
				printAlert(count+=1, "NMAP scan", pkt.ip_saddr, pkt.proto.last, pkt.payload)
			elsif isLiveNikto(pkt.payload)
				printAlert(count+=1, "NIKTO scan", pkt.ip_saddr, pkt.proto.last, pkt.payload)
			elsif isCreditCard(pkt.payload)
				printAlert(count+=1, "Credit card leaked", pkt.ip_saddr, pkt.proto.last, pkt.payload, true)
			end
		end
	end
end

# Reads the web server logs line by line and calls necessary functions to determine 
# if an attack has been performed
def analyzeServerLog(logs)
	count = 0
	File.readlines(logs).collect do |log|
		incident = ''
		if isServerNmap(log)
			printLogs(count+=1, "An NMAP scan", log)
		elsif isServerNikto(log)
			printLogs(count+=1, "A Nikto scan", log)
		elsif isRGMasscan(log)
			printLogs(count+=1, "A Masscan scan", log)
		elsif isShellshock(log)
			printLogs(count+=1, "Shellshock", log)
		elsif isPHPAdmin(log)
			printLogs(count+=1, "Someone looking for phpMyAdmin stuff", log)
		elsif isShellcode(log)
			printLogs(count+=1, "Shellcode", log)
		end
	end
end

# Detects if the user is analyzing live packets or reading in a web server log
def detectIncidents(argv)
	if (argv[0] == '-r' and argv[1] != nil)
		analyzeServerLog(argv[1])
	elsif (argv[0] == '-p' and argv[1] != nil)
		analyzeReadPackets(argv[1])
	else
		analyzeLivePackets
	end
end

detectIncidents(ARGV)	
