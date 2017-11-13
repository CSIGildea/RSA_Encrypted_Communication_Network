package cs.tcd.ie;
/**
 * 
 */

import java.io.IOException;
import java.net.DatagramSocket;
import java.net.DatagramPacket;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.zip.CRC32;
import java.util.zip.Checksum;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import tcdIO.*;

/**
 *
 * Client class
 * 
 * An instance accepts user input 
 *
 */
public class Client extends Node {
	private static KeyPair key = null;
	static boolean sentClientPublicKey = false;
	static boolean receivedServerPublicKey = false;
	static final int DEFAULT_SRC_PORT = 50004;
	static final int DEFAULT_GATEWAY_PORT = 50001;
	static final int DEFAULT_SERVER_PORT = 50002;
	static final String DEFAULT_DST_NODE = "localhost";
	private static final int MAX_PORT_NUMBER = 65000;
	private static final int MIN_PORT_NUMBER = 1000;
	public static final int ACK_INITIATE_CONTACT = 0;
	public static final int ACK_CONTINUE_ENCRYPTED_CONTACT = 1;
	public static final int ACK_ENCRYPTED_CONTACT = 2;
	public static final int ACK_RESEND_PACKET_REQUEST = 3; //Resend Packet
	static int port=DEFAULT_SRC_PORT;
	static int sequenceNumber = 0;
	PublicKey serverPublicKey;
	Boolean acknowledgementReceived = true;
	Terminal terminal;
	InetSocketAddress dstAddress;
	
	/**
	 * Constructor
	 * 	 
	 * Attempts to create socket at given port and create an InetSocketAddress for the destinations
	 */
	Client(Terminal terminal, String dstHost, int dstPort, int srcPort) {
		try {
			this.terminal= terminal;
			dstAddress= new InetSocketAddress(dstHost, dstPort);
			socket= new DatagramSocket(srcPort);
			socket.setReuseAddress(true);
			listener.go();
		}
		catch(java.lang.Exception e) {e.printStackTrace();}
	}

	
	/**
	 * Assume that incoming packets contain a String and print the string.
	 */
	public synchronized void onReceipt(DatagramPacket packet) {
		StringContent content= new StringContent(packet);
		acknowledgementReceived = true;
		this.notify();
		byte[] headerData = new byte[PacketContent.HEADERLENGTH];
		System.arraycopy(packet.getData(), 0, headerData, 0, PacketContent.HEADERLENGTH);
		Header receivedHeader = new Header(headerData);
		if(receivedHeader.getAckNumber()==ACK_RESEND_PACKET_REQUEST)
		{
			acknowledgementReceived=false;
		}
		else 
		{
			if(receivedHeader.getAckNumber()==ACK_INITIATE_CONTACT)
			{
				serverPublicKey = getPublicKey(packet);
				receivedServerPublicKey = true;
				acknowledgementReceived = true;
				terminal.println("Received Server's Public Key for Encryption");
			}
			else
			{
				byte[] encData = new byte[packet.getLength()-PacketContent.HEADERLENGTH];
				System.arraycopy(packet.getData(), PacketContent.HEADERLENGTH, encData, 0, packet.getLength()-PacketContent.HEADERLENGTH);
				terminal.println("Received Decrypted Message:"+decrypt(encData, key.getPrivate()));
			}
			int receivedSequenceNumber = receivedHeader.getSequenceNumber();
			if(sequenceNumber+1==receivedSequenceNumber)
			{
				//terminal.println(content.toString());
				sequenceNumber+=2;
			}
		}
	}
	/**
	 * Sender Method
	 * 
	 */
	public synchronized void start() throws Exception {
		DatagramPacket packet= null;

		byte[] payload= null;
		byte[] header= null;
		byte[] buffer= null;
		
		while(true)
		{
			if(!sentClientPublicKey)
			{
				acknowledgementReceived = false;
				while(!acknowledgementReceived)
				{
					sendPublicKey(DEFAULT_SERVER_PORT);
				}
				sentClientPublicKey = true;
			}
			while(!acknowledgementReceived)
			{
				socket.send(packet);
				terminal.println("Packet re-sent");
				this.wait(3000);
			}
			if(receivedServerPublicKey)
			{
				acknowledgementReceived = false;
				payload= encrypt(terminal.readString("\nString to send: "),serverPublicKey);
				buffer= new byte[PacketContent.HEADERLENGTH+payload.length];
				header = new byte[PacketContent.HEADERLENGTH];

				Header packetHeader = new Header();
				packetHeader.addSourcePort(port);
				packetHeader.addDestinationPort(DEFAULT_SERVER_PORT);
				packetHeader.addSequenceNumber(sequenceNumber);
				packetHeader.addAckNumber(ACK_CONTINUE_ENCRYPTED_CONTACT);
				Checksum checksum = new CRC32();
				checksum.update(payload, 0, payload.length);
				long checksumValue = checksum.getValue();
				packetHeader.addCheckSumNumber((int) checksumValue);
				header = packetHeader.getHeader();

				System.arraycopy(header, 0, buffer, 0, header.length);
				System.arraycopy(payload, 0, buffer, header.length, payload.length);
				terminal.println("Sending packet...");
				InetSocketAddress serverAddress = new InetSocketAddress(DEFAULT_DST_NODE, DEFAULT_SERVER_PORT);
				packet= new DatagramPacket(buffer, buffer.length, serverAddress);
				InetSocketAddress gatewayAddress = new InetSocketAddress(DEFAULT_DST_NODE, DEFAULT_GATEWAY_PORT);
				packet = packetEncapsulation(packet,gatewayAddress);
				socket.send(packet);
				terminal.println("Packet sent");
				sequenceNumber+=2;
				this.wait(3000);
			}
		}
	}


	private void sendPublicKey(int defaultServerPort) throws Exception {
		byte[] publicKey = (key.getPublic()).getEncoded();
		byte[] buffer= new byte[PacketContent.HEADERLENGTH+publicKey.length];
		byte[] header = new byte[PacketContent.HEADERLENGTH];
		
		Header packetHeader = new Header();
		packetHeader.addSourcePort(port);
		packetHeader.addDestinationPort(DEFAULT_SERVER_PORT);
		packetHeader.addSequenceNumber(sequenceNumber);
		packetHeader.addAckNumber(ACK_INITIATE_CONTACT);
		// 0 - Initiate Contact - Sending public key - Save this public key
		// 1 - Encrypted Communication using previously send public key
		// 2 - Encrypted Communication packet accepted
		// 3 - Invalid Sequence Number - Resend Packet
		header = packetHeader.getHeader();
		
		System.arraycopy(header, 0, buffer, 0, header.length);
		System.arraycopy(publicKey, 0, buffer, header.length, publicKey.length);
		terminal.println("Generating and Sending Client RSA Public Key...");
		InetSocketAddress serverAddress = new InetSocketAddress(DEFAULT_DST_NODE, DEFAULT_SERVER_PORT);
		DatagramPacket packet= new DatagramPacket(buffer, buffer.length, serverAddress);
		InetSocketAddress gatewayAddress = new InetSocketAddress(DEFAULT_DST_NODE, DEFAULT_GATEWAY_PORT);
		packet = packetEncapsulation(packet,gatewayAddress);
		try {
			socket.send(packet);
		} catch (IOException e) {
			e.printStackTrace();
		}
		terminal.println("Packet sent");
		this.wait(3000);
	}


	/**
	 * Test method
	 * 
	 * Sends a packet to a given address
	 */
	public static void main(String[] args) {
		try {
			while(!available(port))
			{
				port++;
			}
			gen();
			Terminal terminal= new Terminal("Client-Port:"+port);		
			(new Client(terminal, DEFAULT_DST_NODE, DEFAULT_GATEWAY_PORT, port)).start();
		} catch(java.lang.Exception e) {e.printStackTrace();}
	}
	/**
	 * Checks to see if a specific port is available.
	 *
	 * @param port the port to check for availability
	 */
	public static boolean available(int port) {
	    DatagramSocket datagramSocket = null;
	    ServerSocket serverSocket = null;
	    if (port < MIN_PORT_NUMBER || port > MAX_PORT_NUMBER) {
	        throw new IllegalArgumentException("Invalid start port: " + port);
	    }
	    try {
	        serverSocket = new ServerSocket(port);
	        serverSocket.setReuseAddress(true);
	        datagramSocket = new DatagramSocket(port);
	        datagramSocket.setReuseAddress(true);
	        return true;
	    } catch (Exception e) {
	    } finally {
	        if (datagramSocket != null) {
	            datagramSocket.close();
	        }

	        if (serverSocket != null) {
	            try {
	                serverSocket.close();
	            } catch (IOException e) {
	                /* should not be thrown */
	            }
	        }
	    }
	    return false;
	}
	public static DatagramPacket packetEncapsulation(DatagramPacket packet,InetSocketAddress gatewayAddress) {
		byte[] packetWrapping= new byte[PacketContent.HEADERLENGTH+packet.getLength()];
		System.arraycopy(packet.getData(), 0, packetWrapping, 0, PacketContent.HEADERLENGTH);
		System.arraycopy(packet.getData(), 0, packetWrapping, PacketContent.HEADERLENGTH, packet.getLength());
		packet= new DatagramPacket(packetWrapping, packetWrapping.length, gatewayAddress);
		return packet;
	}
	public static DatagramPacket packetDecapsulation(DatagramPacket packet) {
		byte[] packetContent= new byte[packet.getLength()-PacketContent.HEADERLENGTH];
		System.arraycopy(packet.getData(), PacketContent.HEADERLENGTH, packetContent, 0, packetContent.length);
		return new DatagramPacket(packetContent, packetContent.length);
	}
	
	public static void gen()
	{
		KeyPairGenerator keygenerator = null;
		try
		{
			keygenerator = KeyPairGenerator.getInstance("RSA");
		} catch (NoSuchAlgorithmException e)
		{
			e.printStackTrace();
		}
		keygenerator.initialize(1024);
		key = keygenerator.generateKeyPair();
	}
	
	public static byte[] encrypt(String message, PublicKey pk)
	{
		Cipher cipher = null;
		try
		{
			cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, pk);
		} catch (Exception e)
		{
			e.printStackTrace();
		} 
		byte[] cipherByteArray = null;
		try
		{
			cipherByteArray = cipher.doFinal(message.getBytes());
		} catch (IllegalBlockSizeException | BadPaddingException e)
		{
			e.printStackTrace();
		}
		return cipherByteArray;
	}
	
	public static String decrypt(byte[] encryptedArray, PrivateKey sk)
	{
		byte[] decryption = null;
		Cipher cipher = null;
		try
		{
			cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, sk);
		} catch (Exception e)
		{
			e.printStackTrace();
		} 
		try
		{
			decryption = cipher.doFinal(encryptedArray);
		} catch (IllegalBlockSizeException | BadPaddingException e)
		{
			e.printStackTrace();
		}
		return new String(decryption);
	}
	private PublicKey getPublicKey(DatagramPacket packet) {
		KeyFactory keyFactory = null;
		try {
			keyFactory = KeyFactory.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		byte[] publicKeyBytes = new byte[packet.getLength()-PacketContent.HEADERLENGTH];
		System.arraycopy(packet.getData(),PacketContent.HEADERLENGTH,publicKeyBytes, 0, packet.getLength()-PacketContent.HEADERLENGTH);
	    EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
	    PublicKey publicKey = null;
		try {
			publicKey = keyFactory.generatePublic(publicKeySpec);
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}
		return publicKey;	
	}
}
