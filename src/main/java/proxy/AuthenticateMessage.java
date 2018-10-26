package proxy;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.Charset;
import java.util.Arrays;

public class AuthenticateMessage {

  public final byte[] lmChallengeResponse;
  public final byte[] ntChallengeResponse;
  public final String domainName;
  public final String userName;
  public final String workstation;
  public final byte[] sessionKey;
  public final int flags;
  public final byte[] version;
  public final byte[] mic;

  public AuthenticateMessage(byte[] lmChallengeResponse, byte[] ntChallengeResponse, String domainName, String userName, String workstation, byte[] sessionKey, int flags, byte[] version, byte[] mic) {
    this.lmChallengeResponse = lmChallengeResponse;
    this.ntChallengeResponse = ntChallengeResponse;
    this.domainName = domainName;
    this.userName = userName;
    this.workstation = workstation;
    this.sessionKey = sessionKey;
    this.flags = flags;
    this.version = version;
    this.mic = mic;
  }

  public static AuthenticateMessage fromBytes(byte[] body) {
    ByteBuffer dis = ByteBuffer.wrap(body).order(ByteOrder.LITTLE_ENDIAN);

    byte[] signature = new byte[8];
    dis.get(signature);
    if (!Arrays.equals(signature, NTLMFlags.SIGNATURE))
      throw new IllegalArgumentException("bad signature");

    int messageType = dis.getInt();
    if (messageType != 3) {
      return null;
    }

    // LmChallengeResponseFields
    int lmChallengeResponseLen = dis.getShort();
    int lmChallengeResponseMaxLen = dis.getShort();
    int lmChallengeResponseBufferOffset = dis.getInt();

    // NtChallengeResponseFields
    int ntChallengeResponseLen = dis.getShort();
    int ntChallengeResponseMaxLen = dis.getShort();
    int ntChallengeResponseBufferOffset = dis.getInt();

    // DomainNameFields
    int domainNameLen = dis.getShort();
    int domainNameMaxLen = dis.getShort();
    int domainNameBufferOffset = dis.getInt();

    // UserNameFields
    int userNameLen = dis.getShort();
    int userNameMaxLen = dis.getShort();
    int userNameBufferOffset = dis.getInt();

    // WorkstationFields
    int workstationLen = dis.getShort();
    int workstationMaxLen = dis.getShort();
    int workstationBufferOffset = dis.getInt();

    // EncryptedRandomSessionKeyFields
    int encryptedRandomSessionKeyLen = dis.getShort();
    int encryptedRandomSessionKeyMaxLen = dis.getShort();
    int encryptedRandomSessionKeyBufferOffset = dis.getInt();

    int negotiateFlags = dis.getInt();

    byte[] version = null;
    if (dis.hasRemaining()) {
      version = new byte[8];
      dis.get(version);
    }

    byte[] mic = null; // message integrity
    if (dis.hasRemaining()) {
      mic = new byte[16];
      dis.get(mic);
    }

    Charset encoding = NTLMFlags.encoding(negotiateFlags);
    byte[] lmChallengeResponse = lmChallengeResponseLen > 0 ? Arrays.copyOfRange(body, lmChallengeResponseBufferOffset, lmChallengeResponseBufferOffset + lmChallengeResponseLen) : null;
    byte[] ntChallengeResponse = ntChallengeResponseLen > 0 ? Arrays.copyOfRange(body, ntChallengeResponseBufferOffset, ntChallengeResponseBufferOffset + ntChallengeResponseLen) : null;
    String domainName = domainNameLen > 0 ? new String(body, domainNameBufferOffset, domainNameLen, encoding) : null;
    String userName = userNameLen > 0 ? new String(body, userNameBufferOffset, userNameLen, encoding) : null;
    String workstation = workstationLen > 0 ? new String(body, workstationBufferOffset, workstationLen, encoding) : null;
    byte[] encryptedRandomSessionKey = encryptedRandomSessionKeyLen > 0 ? Arrays.copyOfRange(body, encryptedRandomSessionKeyBufferOffset, encryptedRandomSessionKeyBufferOffset + encryptedRandomSessionKeyLen) : null;

    return new AuthenticateMessage(lmChallengeResponse, ntChallengeResponse, domainName, userName, workstation, encryptedRandomSessionKey, negotiateFlags, version, mic);
  }
}
