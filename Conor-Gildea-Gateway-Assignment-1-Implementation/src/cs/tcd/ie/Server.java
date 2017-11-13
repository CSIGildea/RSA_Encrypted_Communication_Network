package cs.tcd.ie;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.zip.CRC32;
import java.util.zip.Checksum;
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

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import tcdIO.Terminal;

public class Server extends Node {
	static final int DEFAULT_SERVER_PORT = 50002;
	static final String DEFAULT_DST_NODE = "localhost";
	public static final int ACK_INITIATE_CONTACT = 0;
	public static final int ACK_CONTINUE_ENCRYPTED_CONTACT = 1;
	public static final int ACK_ENCRYPTED_CONTACT = 2;
	public static final int ACK_RESEND_PACKET_REQUEST = 3; //Resend Packet
	ArrayList<Integer> portNumbers = new ArrayList<Integer>();
	ArrayList<Integer> sequenceNumbers = new ArrayList<Integer>();
	ArrayList<PublicKey> receivedPublicKeys= new ArrayList<PublicKey>();
	static KeyPair serverKeys;
	Terminal terminal;
	
	/*
	 * 
	 */
	Server(Terminal terminal, int port) {
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
		StringContent content= new StringContent(packet);
		InetSocketAddress dstAddress;
		
		byte[] headerData = new byte[PacketContent.HEADERLENGTH];
		System.arraycopy(packet.getData(), 0, headerData, 0, PacketContent.HEADERLENGTH);
		Header receivedHeader = new Header(headerData);
		int clientPort = receivedHeader.getSourcePort();
		int sequenceNumber = receivedHeader.getSequenceNumber();
		
		if(!portNumbers.contains(clientPort))
		{
			portNumbers.add(clientPort);
			sequenceNumbers.add(0);
			if(receivedHeader.getAckNumber()==0)
			{
			    PublicKey publicKey = getPublicKey(packet);
				receivedPublicKeys.add(publicKey);
				String output = new String(publicKey.getEncoded());
				terminal.println("Received Key from "+clientPort+":"+output);
				sendPublicKey(clientPort,sequenceNumber+1, packet.getPort());
				int indexExpectedPort = portNumbers.indexOf(clientPort);
				sequenceNumbers.set(indexExpectedPort,sequenceNumbers.get(indexExpectedPort)+2);
			}
		}
		else
		{
			int indexExpectedPort = portNumbers.indexOf(clientPort);
			PublicKey clientPublicKey = receivedPublicKeys.get(indexExpectedPort);
			int expectedSequenceNumber =sequenceNumbers.get(indexExpectedPort);
			byte[] packetData = new byte[packet.getLength()-PacketContent.HEADERLENGTH];
			System.arraycopy(packet.getData(), PacketContent.HEADERLENGTH, packetData, 0, packet.getLength()-PacketContent.HEADERLENGTH);
			Checksum checksum = new CRC32();
			checksum.update(packetData, 0, packetData.length);
			long checksumValue = checksum.getValue();
			if(expectedSequenceNumber==sequenceNumber&&(receivedHeader.getCheckSumNumber()==(int)checksumValue))
			{
				DatagramPacket response;
				Header responseHeader = new Header();
				responseHeader.addSourcePort(DEFAULT_SERVER_PORT);
				responseHeader.addDestinationPort(clientPort);
				responseHeader.addSequenceNumber(expectedSequenceNumber+1);
				responseHeader.addAckNumber(ACK_CONTINUE_ENCRYPTED_CONTACT);
				byte[] encData = new byte[packet.getLength()-PacketContent.HEADERLENGTH];
				System.arraycopy(packet.getData(), PacketContent.HEADERLENGTH, encData, 0,encData.length);
				terminal.println(packet.getAddress()+":"+clientPort+": "+decrypt(encData, serverKeys.getPrivate()));
				sequenceNumbers.set(indexExpectedPort,sequenceNumbers.get(indexExpectedPort)+1);
				byte[] payload = encrypt("Ok",clientPublicKey);
				Checksum checksumResponse = new CRC32();
				checksum.update(payload, 0, payload.length);
				long checksumResponseValue = checksumResponse.getValue();
				responseHeader.addCheckSumNumber((int) checksumResponseValue);
				byte[] buffer = new byte[payload.length+responseHeader.getHeader().length];
				System.arraycopy(responseHeader.getHeader(), 0,buffer, 0, PacketContent.HEADERLENGTH);
				System.arraycopy(payload, 0 ,buffer, PacketContent.HEADERLENGTH, payload.length);
				dstAddress = new InetSocketAddress(DEFAULT_DST_NODE,packet.getPort());
				response = new DatagramPacket(buffer, buffer.length, packet.getSocketAddress());
				response = packetEncapsulation(response,dstAddress);
				try {
					socket.send(response);
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				sequenceNumbers.set(indexExpectedPort,sequenceNumbers.get(indexExpectedPort)+1);
			}
			else
			{
				DatagramPacket response;
				Header responseHeader = new Header();
				responseHeader.addSourcePort(DEFAULT_SERVER_PORT);
				responseHeader.addDestinationPort(clientPort);
				responseHeader.addSequenceNumber(expectedSequenceNumber+1);
				responseHeader.addAckNumber(ACK_RESEND_PACKET_REQUEST);
				byte[] encData = new byte[packet.getLength()-PacketContent.HEADERLENGTH];
				System.arraycopy(packet.getData(), PacketContent.HEADERLENGTH, encData, 0,encData.length);
				terminal.println(packet.getAddress()+":"+clientPort+": "+decrypt(encData, serverKeys.getPrivate()));
				sequenceNumbers.set(indexExpectedPort,sequenceNumbers.get(indexExpectedPort)+1);
				byte[] payload = encrypt("ERROR:"+"Expected sequence:"+sequenceNumbers.get(indexExpectedPort)+
							" Received sequence number:"+sequenceNumber+"Port:"+clientPort+
							"Sequence:"+expectedSequenceNumber,clientPublicKey);
				Checksum checksumResponse = new CRC32();
				checksum.update(payload, 0, payload.length);
				long checksumResponseValue = checksumResponse.getValue();
				responseHeader.addCheckSumNumber((int) checksumResponseValue);
				byte[] buffer = new byte[payload.length+responseHeader.getHeader().length];
				System.arraycopy(responseHeader.getHeader(), 0,buffer, 0, PacketContent.HEADERLENGTH);
				System.arraycopy(payload, 0 ,buffer, PacketContent.HEADERLENGTH, payload.length);
				dstAddress = new InetSocketAddress(DEFAULT_DST_NODE,packet.getPort());
				response = new DatagramPacket(buffer, buffer.length, packet.getSocketAddress());
				response = packetEncapsulation(response,dstAddress);
				try {
					socket.send(response);
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		}
	}


	public synchronized void start() throws Exception {
		terminal.println("Waiting for contact");
		this.wait();
	}

	/*
	 * 
	 */
	public static void main(String[] args) {
		gen();
		try {					
			Terminal terminal= new Terminal("Server");
			(new Server(terminal, DEFAULT_SERVER_PORT)).start();
			terminal.println("Program completed");
		} catch(java.lang.Exception e) {e.printStackTrace();}
	}
	private void sendPublicKey(int clientPort, int sequenceNumber, int gatewayPort) {
		byte[] publicKey = (serverKeys.getPublic()).getEncoded();
		//System.out.println(decrypt(enc, key.getPrivate()));
		byte[] buffer= new byte[PacketContent.HEADERLENGTH+publicKey.length];
		byte[] header = new byte[PacketContent.HEADERLENGTH];
		
		Header packetHeader = new Header();
		packetHeader.addSourcePort(DEFAULT_SERVER_PORT);
		packetHeader.addDestinationPort(clientPort);
		packetHeader.addSequenceNumber(sequenceNumber);
		packetHeader.addAckNumber(ACK_INITIATE_CONTACT);
		header = packetHeader.getHeader();
		
		System.arraycopy(header, 0, buffer, 0, header.length);
		System.arraycopy(publicKey, 0, buffer, header.length, publicKey.length);
		terminal.println("Sending packet...");
		InetSocketAddress clientAddress = new InetSocketAddress(DEFAULT_DST_NODE, clientPort);
		DatagramPacket packet= new DatagramPacket(buffer, buffer.length, clientAddress);
		InetSocketAddress gatewayAddress = new InetSocketAddress(DEFAULT_DST_NODE, gatewayPort);
		packet = packetEncapsulation(packet,gatewayAddress);
		String output = null;
		try {
			output = new String(buffer, "UTF-8");
		} catch (UnsupportedEncodingException e1) {
			e1.printStackTrace();
		}
		terminal.println(output);
		try {
			socket.send(packet);
		} catch (IOException e) {
			e.printStackTrace();
		}
		terminal.println("Public Key sent to "+clientPort+" via "+gatewayPort);
	}
	public static DatagramPacket packetEncapsulation(DatagramPacket packet,InetSocketAddress gatewayAddress) {
		byte[] packetWrapping= new byte[PacketContent.HEADERLENGTH+packet.getLength()];
		System.arraycopy(packet.getData(), 0, packetWrapping, 0, PacketContent.HEADERLENGTH);
		System.arraycopy(packet.getData(), 0, packetWrapping, PacketContent.HEADERLENGTH, packet.getLength());
		packet= new DatagramPacket(packetWrapping, packetWrapping.length, gatewayAddress);
		return packet;
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
	
	public static void gen()
	{
		KeyPairGenerator keygen = null;
		try
		{
			keygen = KeyPairGenerator.getInstance("RSA");
		} catch (NoSuchAlgorithmException e)
		{
			e.printStackTrace();
		}
		keygen.initialize(1024);
		serverKeys = keygen.generateKeyPair();
	}
	
	public static byte[] encrypt(String message, PublicKey publicKey)
	{
		Cipher cipher = null;
		try
		{
			cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
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
		byte[] deccryption = null;
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
			deccryption = cipher.doFinal(encryptedArray);
		} catch (IllegalBlockSizeException | BadPaddingException e)
		{
			e.printStackTrace();
		}
		return new String(deccryption);
	}
}
