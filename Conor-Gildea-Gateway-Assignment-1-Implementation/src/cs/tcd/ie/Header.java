package cs.tcd.ie;

import java.nio.ByteBuffer;
import java.util.Arrays;

public class Header {
	public static final int SRC_PORT_OFFSET = 0;
	public static final int SRC_PORT_LENGTH = 4;
	public static final int DST_PORT_OFFSET = 4;
	public static final int DST_PORT_LENGTH = 4;
	public static final int SEQUENCE_NUM_OFFSET = 8;
	public static final int SEQUENCE_NUM_LENGTH = 8;
	public static final int ACK_NUM_OFFSET = 16;
	public static final int ACK_NUM_LENGTH = 8;
	public static final int CHECK_SUM_NUM_OFFSET = 24;
	public static final int CHECK_SUM_NUM_LENGTH = 4;

	
	public static byte[] header=new byte[PacketContent.HEADERLENGTH];
	Header()
	{
		this.header = header;
	}
	Header(byte[] inputtedHeader)
	{
		this.header = inputtedHeader;
	}
	public void addSourcePort(int srcPort) {
		byte[] portArray= ByteBuffer.allocate(SRC_PORT_LENGTH).putInt(srcPort).array();
		System.arraycopy(portArray,0,this.header,0,SRC_PORT_LENGTH);
	}
	public int getSourcePort() {
		byte[] portArray= ByteBuffer.allocate(SRC_PORT_LENGTH).array();
		System.arraycopy(this.header,0,portArray,0,SRC_PORT_LENGTH);
		return ByteBuffer.wrap(portArray).getInt();
	}
	public void addDestinationPort(int dstPort) {
		byte[] portArray= ByteBuffer.allocate(DST_PORT_LENGTH).putInt(dstPort).array();
		System.arraycopy(portArray,0,this.header,DST_PORT_OFFSET,DST_PORT_LENGTH);
	}
	public int getDestinationPort() {
		byte[] portArray= ByteBuffer.allocate(DST_PORT_LENGTH).array();
		System.arraycopy(this.header,DST_PORT_OFFSET,portArray,0,DST_PORT_LENGTH);
		return ByteBuffer.wrap(portArray).getInt();
	}
	public void addSequenceNumber(int sequenceNumber) {
		byte[] sequenceNumArray= ByteBuffer.allocate(SEQUENCE_NUM_LENGTH).putInt(sequenceNumber).array();
		System.arraycopy(sequenceNumArray,0,this.header,SEQUENCE_NUM_OFFSET,SEQUENCE_NUM_LENGTH);
	}
	public int getSequenceNumber() {
		byte[] sequenceNumArray= ByteBuffer.allocate(SEQUENCE_NUM_LENGTH).array();
		System.arraycopy(this.header,SEQUENCE_NUM_OFFSET,sequenceNumArray,0,SEQUENCE_NUM_LENGTH);
		return ByteBuffer.wrap(sequenceNumArray).getInt();
	}
	public void addAckNumber(int ackNumber) {
		byte[] ackNumArray= ByteBuffer.allocate(ACK_NUM_LENGTH).putInt(ackNumber).array();
		System.arraycopy(ackNumArray,0,this.header,ACK_NUM_OFFSET,ACK_NUM_LENGTH);
	}
	public int getAckNumber() {
		byte[] ackNumArray= ByteBuffer.allocate(ACK_NUM_LENGTH).array();
		System.arraycopy(this.header,ACK_NUM_OFFSET,ackNumArray,0,SEQUENCE_NUM_LENGTH);
		return ByteBuffer.wrap(ackNumArray).getInt();
	}
	public void addCheckSumNumber(int checkSumNumber) {
		byte[] checkSumNumArray= ByteBuffer.allocate(CHECK_SUM_NUM_LENGTH).putInt(checkSumNumber).array();
		System.arraycopy(checkSumNumArray,0,this.header,CHECK_SUM_NUM_OFFSET,CHECK_SUM_NUM_LENGTH);
	}
	public int getCheckSumNumber() {
		byte[] checkSumNumArray= ByteBuffer.allocate(ACK_NUM_LENGTH).array();
		System.arraycopy(this.header,CHECK_SUM_NUM_OFFSET,checkSumNumArray,0,CHECK_SUM_NUM_LENGTH);
		return ByteBuffer.wrap(checkSumNumArray).getInt();
	}
	public byte[] getHeader() {
		return this.header;
	}
}
