package cs.tcd.ie;

import java.net.DatagramPacket;

public interface PacketContent {
	
	public static byte HEADERLENGTH = 35;
	
	public String toString();
	public DatagramPacket toDatagramPacket();
}
