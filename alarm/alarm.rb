require 'packetfu'

def isNullScan(packet)
	isNULL = false
	if packet.tcp_flags.urg == 0 and packet.tcp_flags.ack == 0 and packet.tcp_flags.psh == 0 and packet.tcp_flags.rst == 0 and packet.tcp_flags.syn == 0 and packet.tcp_flags.fin == 0
		isNULL = true
	end
	isNULL
end

def isFinScan(packet)
	isFIN = false
	if packet.tcp_flags.urg == 0 and packet.tcp_flags.ack == 0 and packet.tcp_flags.psh == 0 and packet.tcp_flags.rst == 0 and packet.tcp_flags.syn == 0 and packet.tcp_flags.fin == 1
		isFIN = true
	end
	isFIN
end

def isXmasScan(packet)
	isXMAS = false
	if packet.tcp_flags.urg == 1 and packet.tcp_flags.ack == 0 and packet.tcp_flags.psh == 1 and packet.tcp_flags.rst == 0 and packet.tcp_flags.syn == 0 and packet.tcp_flags.fin = 1
		isXMAS = true
	end
	isXMAS
end

def isOtherNmap(packet)
	isOtherNMAP = false
	if packet.match(/Nmap/i) != nil
		isOtherNMAP = true
	end
	isOtherNMAP	
end

def isNiktoScan(packet)
	isNIKTO = false
	if packet.match(/Nikto/i) or packet.match(/HEAD/) != nil
		isNIKTO = true
	end
	isNIKTO	
end

def isCreditCard(packet)
	# all regex expressions taken from "http://www.regular-expressions.info/creditcard.html"
	isCC = false
	
	# visa credit card format
	if packet.match(/^4[0-9]{12}(?:[0-9]{3})?$/) != nil
		isCC = true
	# mastercard credit card format
	elsif packet.match(/^5[1-5][0-9]{14}$/) != nil
		isCC = true
	# american express credit card format
	elsif packet.match(/^3[47][0-9]{13}$/) != nil
		isCC = true
	# diners club credit card format
	elsif packet.match(/^3(?:0[0-5]|[68][0-9])[0-9]{11}$/) != nil
		isCC = true
	# discover credit card format
	elsif packet.match(/^6(?:011|5[0-9]{2})[0-9]{12}$/) != nil
		isCC = true
	# jcb credit card format
	elseif packet.match(/^(?:2131|1800|35\d{3})\d{11}$/) != nil
		isCC = true
	end
	isCC
end

def isRGMasscan(log)
	isMasscan = false
	if log.match(/masscan/i) != nil
		isMasscan = true
	end
	isMasscan
end

def analyzeLivePackets()
	count = 0
	cap = PacketFu::Capture.new(:start => true, :iface => 'eth0', :promisc => true)
	cap.stream.each do |p|
		pkt = PacketFu::Packet.parse(p)
		incident = ""
		if pkt.is_ip? and pkt.is_tcp?
			if isNullScan(pkt)
				incident = "NULL"
			elsif isFinScan(pkt)
				incident = "FIN"
			elsif isXmasScan(pkt)
				incident = "XMAS"
			elsif isOtherNmap(pkt.payload)
				incident = "NMAP"
			elsif isNiktoScan(pkt.payload)
				incident = "NIKTO"
			elsif isCreditCard(pkt.payload)
				incident = "CREDIT CARD"
			else
				incident = ""
			end
		
			if incident == ""
				packet_info = [pkt.ip_saddr, pkt.ip_daddr, pkt.size, pkt.proto.last]
	#			puts "#{count}. %-15s-> %-15s %-4d %s" %packet_info
				count = count + 1
			end
		end
	end
end		

def print(count, incident, sourceIP, protocol, payload)
	puts "#{count}. ALERT: #{incident} is detected from #{sourceIP} #{protocol} #{payload}"
end

def printLogs(count, incident, log)
	
	print(count, incident,) 
end

def analyzeServerLog(logs)
	count = 1
	File.readlines(logs).collect do |log|
		incident = ''
		if isOtherNmap(log)
			incident = "An NMAP scan"
			printLogs(count, incident, log)
#		elsif isNiktoScan(log)
#			incident = "A Nikto scan "
#		elsif isRGMasscan(log)
#			incident = "A Masscan "
		end
	end
end

def detectIncidents(argv)
	if (argv[0] == '-r' and argv[1] != nil)
		analyzeServerLog(argv[1])
	else
		analyzeLivePackets
	end
end



detectIncidents(ARGV)	
