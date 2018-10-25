package proxy;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

public class AuthenticateMessage {

  public final byte[] lmChallengeResponse;
  public final byte[] ntChallengeResponse;
  public final String domainName;
  public final String userName;
  public final String workstation;
  public final byte[] sessionKey;
  public final int flags;
  public final byte[] mic;

  public AuthenticateMessage(byte[] lmChallengeResponse, byte[] ntChallengeResponse, String domainName, String userName, String workstation, byte[] sessionKey, int flags, byte[] mic) {
    this.lmChallengeResponse = lmChallengeResponse;
    this.ntChallengeResponse = ntChallengeResponse;
    this.domainName = domainName;
    this.userName = userName;
    this.workstation = workstation;
    this.sessionKey = sessionKey;
    this.flags = flags;
    this.mic = mic;
  }

  public static AuthenticateMessage fromBytes(byte[] body) {
    ByteBuffer dis = ByteBuffer.wrap(body).order(ByteOrder.LITTLE_ENDIAN);

    byte[] signature = new byte[8];
    dis.get(signature);

    int messageType = dis.getInt();
    if (messageType != 3) {
      return null;
    }

    // LmChallengeResponseFields
    short lmChallengeResponseLen = dis.getShort();
    short lmChallengeResponseMaxLen = dis.getShort();
    int lmChallengeResponseBufferOffset = dis.getInt();

    // NtChallengeResponseFields
    short ntChallengeResponseLen = dis.getShort();
    short ntChallengeResponseMaxLen = dis.getShort();
    int ntChallengeResponseBufferOffset = dis.getInt();

    // DomainNameFields
    short domainNameLen = dis.getShort();
    short domainNameMaxLen = dis.getShort();
    int domainNameBufferOffset = dis.getInt();

    // UserNameFields
    short userNameLen = dis.getShort();
    short userNameMaxLen = dis.getShort();
    int userNameBufferOffset = dis.getInt();

    // WorkstationFields
    short workstationLen = dis.getShort();
    short workstationMaxLen = dis.getShort();
    int workstationBufferOffset = dis.getInt();

    // EncryptedRandomSessionKeyFields
    short encryptedRandomSessionKeyLen = dis.getShort();
    short encryptedRandomSessionKeyMaxLen = dis.getShort();
    int encryptedRandomSessionKeyBufferOffset = dis.getInt();

    int negotiateFlags = dis.getInt();

    byte[] version = new byte[8];
    dis.get(version);

    byte[] mic = new byte[16]; // message integrity
    dis.get(mic);

    byte[] lmChallengeResponse = lmChallengeResponseLen > 0 ? Arrays.copyOfRange(body, lmChallengeResponseBufferOffset, lmChallengeResponseBufferOffset + lmChallengeResponseLen) : null;
    byte[] ntChallengeResponse = ntChallengeResponseLen > 0 ? Arrays.copyOfRange(body, ntChallengeResponseBufferOffset, ntChallengeResponseBufferOffset + ntChallengeResponseLen) : null;
    String domainName = domainNameLen > 0 ? new String(body, domainNameBufferOffset, domainNameLen) : null;
    String userName = userNameLen > 0 ? new String(body, userNameBufferOffset, userNameLen) : null;
    String workstation = workstationLen > 0 ? new String(body, workstationBufferOffset, workstationLen) : null;
    byte[] encryptedRandomSessionKey = encryptedRandomSessionKeyLen > 0 ? Arrays.copyOfRange(body, encryptedRandomSessionKeyBufferOffset, encryptedRandomSessionKeyBufferOffset + encryptedRandomSessionKeyLen) : null;

    return new AuthenticateMessage(lmChallengeResponse, ntChallengeResponse, domainName, userName, workstation, encryptedRandomSessionKey, negotiateFlags, mic);
  }
}
