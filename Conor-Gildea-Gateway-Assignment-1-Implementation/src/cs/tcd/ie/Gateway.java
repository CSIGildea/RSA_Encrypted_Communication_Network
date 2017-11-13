package cs.tcd.ie;
/**
 * 
 */

import java.net.DatagramSocket;
import java.awt.List;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.Collection;

import tcdIO.*;
/**
 * 
 * @author gildeaco
 *
 */
public class Gateway extends Node{
	Terminal terminal;
	static final String DEFAULT_DST_NODE = "localhost";
	static final int DEFAULT_GATEWAY_PORT = 50001;

	Gateway(Terminal terminal, int port) {
		try {
			this.terminal= terminal;
			socket= new DatagramSocket(port);
			listener.go();
		}
		catch(java.lang.Exception e) {e.printStackTrace();}
	}

	/**
	 * Assume that incoming packets contain a String and print the string.
	 */
	public void onReceipt(DatagramPacket packet) {
		packet = packetDecapsulation(packet);
		StringContent content= new StringContent(packet);
		InetSocketAddress dstAddress = null;

		byte[] headerData = new byte[PacketContent.HEADERLENGTH];
		System.arraycopy(packet.getData(), 0, headerData, 0,PacketContent.HEADERLENGTH);
		Header receivedHeader = new Header(headerData);
		terminal.println("\nReceived from:"+receivedHeader.getSourcePort()+"\nDestination:"
										+receivedHeader.getDestinationPort()+"\nEncrypted Communication:"+content.toString()+"\n");
		int dstPort = receivedHeader.getDestinationPort();
		dstAddress=new InetSocketAddress("localhost",dstPort);
		DatagramPacket toServer;
		byte[] serverPacket = new byte[packet.getData().length]; 
		System.arraycopy(packet.getData(), 0, serverPacket, 0, packet.getLength());
		toServer= new DatagramPacket(serverPacket, serverPacket.length, dstAddress);
		toServer.setSocketAddress(dstAddress);
		try {
			socket.send(toServer);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public synchronized void start() throws Exception {
		terminal.println("Waiting for contact");
		this.wait();
	}

	public static void main(String[] args) 
	{
		try {					
			Terminal terminal= new Terminal("Gateway");
			(new Gateway(terminal, DEFAULT_GATEWAY_PORT)).start();
			terminal.println("Program completed");
		} catch(java.lang.Exception e) {e.printStackTrace();}
	}
	public static DatagramPacket packetDecapsulation(DatagramPacket packet) 
	{
		byte[] packetContent= new byte[packet.getLength()-PacketContent.HEADERLENGTH];
		byte[] packetContentHeader= new byte[PacketContent.HEADERLENGTH];
		System.arraycopy(packet.getData(),0, packetContentHeader, 0, PacketContent.HEADERLENGTH);
		Header insideHeader = new Header(packetContentHeader);
		int destinationPort = insideHeader.getDestinationPort();
		InetSocketAddress dstAddress = new InetSocketAddress(DEFAULT_DST_NODE,destinationPort);
		System.arraycopy(packet.getData(), PacketContent.HEADERLENGTH, packetContent, 0, packetContent.length);
		return new DatagramPacket(packetContent, packetContent.length,dstAddress);
	}
}
