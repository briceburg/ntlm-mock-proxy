package proxy;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class NegotiateMessage {

  public final String domainName;
  public final String workstation;
  public final int flags;

  public NegotiateMessage(String domainName, String workstation, int flags) {
    this.domainName = domainName;
    this.workstation = workstation;
    this.flags = flags;
  }

  public static NegotiateMessage fromBytes(byte[] message) {
    ByteBuffer dis = ByteBuffer.wrap(message).order(ByteOrder.LITTLE_ENDIAN);

    byte[] signature = new byte[8];
    dis.get(signature);

    int messageType = dis.getInt();
    if (messageType != 1) {
      return null;
    }

    // NegotiateFlags
    int negotiateFlags = dis.getInt();

    // DomainNameFields
    int domainNameLen = dis.getShort();
    int domainNameMaxLen = dis.getShort();
    int domainNameBufferOffset = dis.getInt();

    // WorkstationFields
    int workstationLen = dis.getShort();
    int workstationMaxLen = dis.getShort();
    int workstationBufferOffset = dis.getInt();

    // Version
    byte[] version;
    if (dis.hasRemaining()) {
      version = new byte[8];
      dis.get(version);
    }

    String domainName = domainNameLen > 0 ? NTLMFlags.decode(message, domainNameBufferOffset, domainNameLen, negotiateFlags) : null;
    String workstation = workstationLen > 0 ? NTLMFlags.decode(message, workstationBufferOffset, workstationLen, negotiateFlags) : null;
    return new NegotiateMessage(domainName, workstation, negotiateFlags);
  }
}
