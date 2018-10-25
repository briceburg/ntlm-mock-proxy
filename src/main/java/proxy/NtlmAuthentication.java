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
    boolean userMatch = expectedUser == null || expectedUser.equalsIgnoreCase(authMessage.userName);

    String expectedDomain = System.getProperty("ntlm.domain");
    boolean domainMatch = expectedDomain == null || expectedDomain.equalsIgnoreCase(authMessage.domainName);

    return userMatch && domainMatch;
  }

  private String generateChallenge(String auth) throws IOException {
    NegotiateMessage negotiate = NegotiateMessage.fromBytes(Base64.getDecoder().decode(auth.substring(5)));
    if (negotiate == null)
      return null;

    ChallengeMessage challengeMessage = new ChallengeMessage(null, null, 0);
    return "NTLM " + Base64.getEncoder().encodeToString(challengeMessage.toBytes());
  }

  private String getNtlmHeader(HttpServletRequest req) {
    for (String s : Collections.list(req.getHeaders("Proxy-Authorization"))) {
      if (s.toLowerCase().startsWith("ntlm "))
        return s;
    }
    return null;
  }
}
