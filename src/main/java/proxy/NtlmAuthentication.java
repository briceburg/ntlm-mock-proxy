package proxy;

import java.io.IOException;
import java.util.Base64;
import java.util.Collections;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class NtlmAuthentication {

  public boolean handleAuthentication(HttpServletRequest request, HttpServletResponse response) throws IOException {
    String auth = getNtlmHeader(request);
    if (auth == null) {
      response.addHeader("Connection", "close");
      response.addHeader("Proxy-Authenticate", "NTLM");
      return false;
    }
    if (hasValidCredentials(auth)) {
      return true;
    }

    response.addHeader("Connection", "keep-alive");
    response.addHeader("Proxy-Authenticate", generateChallenge(auth));
    return false;
  }

  private boolean hasValidCredentials(String header) {
    AuthenticateMessage authMessage = AuthenticateMessage.fromBytes(Base64.getDecoder().decode(header.substring(5)));
    if (authMessage == null)
      return false;

    String expectedUser = System.getProperty("ntlm.user");
    if (expectedUser != null && !expectedUser.equalsIgnoreCase(authMessage.userName)) {
      System.out.println("rejected; expected user=" + expectedUser + ", actual=" + authMessage.userName);
      return false;
    }

    String expectedDomain = System.getProperty("ntlm.domain");
    if (expectedDomain != null && !expectedDomain.equalsIgnoreCase(authMessage.domainName)) {
      System.out.println("rejected; expected domain=" + expectedDomain + ", actual=" + authMessage.domainName);
      return false;
    }

    return true;
  }

  private String generateChallenge(String auth) throws IOException {
    NegotiateMessage negotiate = NegotiateMessage.fromBytes(Base64.getDecoder().decode(auth.substring(5)));
    if (negotiate == null)
      return null;

    ChallengeMessage challengeMessage = new ChallengeMessage(null, null, negotiateCharset(negotiate.flags));
    return "NTLM " + Base64.getEncoder().encodeToString(challengeMessage.toBytes());
  }

  private int negotiateCharset(int base) {
    if (NTLMFlags.unicode(base))
      return NTLMFlags.NTLMSSP_NEGOTIATE_UNICODE;
    if (NTLMFlags.oem(base))
      return NTLMFlags.NTLM_NEGOTIATE_OEM;
    return 0;
  }

  private String getNtlmHeader(HttpServletRequest req) {
    for (String s : Collections.list(req.getHeaders("Proxy-Authorization"))) {
      if (s.toLowerCase().startsWith("ntlm "))
        return s;
    }
    return null;
  }
}
