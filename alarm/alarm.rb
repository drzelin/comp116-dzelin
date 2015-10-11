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

def parsePackets()
	count = 0
	cap = PacketFu::Capture.new(:start => true, :iface => 'eth0', :promisc => true)
	cap.stream.each do |p|
		pkt = ::PacketFu::Packet.parse(p)
		incident = ""
		if isNullScan(pkt)
			incident = "NULL"
		elsif isFinScan(pkt)
			incident = "FIN"
		elsif isXmasScan(pkt)
			incident = "XMAS"
		else
			incident = ""
		end
		
		if incident == ""
			packet_info = [pkt.ip_saddr, pkt.ip_daddr, pkt.size, pkt.proto.last]
			puts "#{count}. %-15s-> %-15s %-4d %s" %packet_info
			count = count + 1
		end
	end
end		

parsePackets
