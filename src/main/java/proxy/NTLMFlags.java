package proxy;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

public interface NTLMFlags {

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

  static byte[] encode(String s, int flags) {
    Charset charset = unicode(flags) ? StandardCharsets.UTF_16LE : StandardCharsets.UTF_8;
    return s.getBytes(charset);
  }

  static String decode(byte[] data, int off, int len, int flags) {
    Charset charset = unicode(flags) ? StandardCharsets.UTF_16LE : StandardCharsets.UTF_8;
    return new String(data, off, len, charset);
  }
}
