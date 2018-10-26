package red.sigil.proxy;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.Charset;
import java.util.Arrays;

public class NegotiateMessage {

  public final String domainName;
  public final String workstation;
  public final int flags;
  public final byte[] version;

  public NegotiateMessage(String domainName, String workstation, int flags, byte[] version) {
    this.domainName = domainName;
    this.workstation = workstation;
    this.flags = flags;
    this.version = version;
  }

  public static NegotiateMessage fromBytes(byte[] message) {
    ByteBuffer dis = ByteBuffer.wrap(message).order(ByteOrder.LITTLE_ENDIAN);

    byte[] signature = new byte[8];
    dis.get(signature);
    if (!Arrays.equals(signature, NTLMFlags.SIGNATURE))
      throw new IllegalArgumentException("bad signature");

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
    byte[] version = null;
    if (dis.hasRemaining()) {
      version = new byte[8];
      dis.get(version);
    }

    Charset encoding = NTLMFlags.encoding(negotiateFlags);
    String domainName = domainNameLen > 0 ? new String(message, domainNameBufferOffset, domainNameLen, encoding) : null;
    String workstation = workstationLen > 0 ? new String(message, workstationBufferOffset, workstationLen, encoding) : null;
    return new NegotiateMessage(domainName, workstation, negotiateFlags, version);
  }
}
