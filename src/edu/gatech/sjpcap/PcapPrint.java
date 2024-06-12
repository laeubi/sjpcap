package edu.gatech.sjpcap;

import java.io.IOException;

public class PcapPrint {

	public static void main(String[] args) throws IOException {

		if(args.length < 1) {
			System.err.println("Please supply a file!");
			return;
		}
		PcapParser pcapParser = new PcapParser();
		if(pcapParser.openFile(args[0]) < 0) {
			System.err.println("Failed to open " + args[0] + ", exiting.");
			return;
		}
		Packet packet = pcapParser.getPacket();
		while(packet != Packet.EOF) {
			if(!(packet instanceof IPPacket)) {
				packet = pcapParser.getPacket();
				continue;
			}
			System.out.println("--PACKET--");
			IPPacket ipPacket = (IPPacket)packet;
			System.out.println("TIME " + ipPacket.timestamp / 1000);
			System.out.println("SRC " + ipPacket.src_ip.getHostAddress());
			System.out.println("DST " + ipPacket.dst_ip.getHostAddress());
			if(ipPacket instanceof UDPPacket) {
				UDPPacket udpPacket = (UDPPacket)ipPacket;
				System.out.println("SRC PORT " + udpPacket.src_port);
				System.out.println("DST PORT " + udpPacket.dst_port);
				System.out.println("PAYLOAD LEN " + udpPacket.data.length);
			}
			if(ipPacket instanceof TCPPacket) {
				TCPPacket tcpPacket = (TCPPacket)ipPacket;
				System.out.println("SRC PORT " + tcpPacket.src_port);
				System.out.println("DST PORT " + tcpPacket.dst_port);
				System.out.println("PAYLOAD LEN " + tcpPacket.data.length);
			}
			packet = pcapParser.getPacket();
		}
		pcapParser.closeFile();
	}
}