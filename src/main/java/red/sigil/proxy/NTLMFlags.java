package red.sigil.proxy;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

public interface NTLMFlags {

  byte[] SIGNATURE = {'N', 'T', 'L', 'M', 'S', 'S', 'P', 0};

  int NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY = 1 << 19;
  int NTLMSSP_TARGET_TYPE_SERVER = 1 << 17;
  int NTLMSSP_TARGET_TYPE_DOMAIN = 1 << 16;
  int NTLM_NEGOTIATE_OEM = 1 << 1;
  int NTLMSSP_NEGOTIATE_UNICODE = 1;

  static boolean unicode(int flags) {
    return (flags & NTLMSSP_NEGOTIATE_UNICODE) != 0;
  }

  static boolean oem(int flags) {
    return (flags & NTLMSSP_NEGOTIATE_UNICODE) != 0;
  }

  static Charset encoding(int flags) {
    return unicode(flags) ? StandardCharsets.UTF_16LE : StandardCharsets.UTF_8;
  }

}
