package proxy;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpEntityEnclosingRequest;
import org.apache.http.HttpHost;
import org.apache.http.HttpRequest;
import org.apache.http.MethodNotSupportedException;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.entity.BasicHttpEntity;
import org.apache.http.impl.DefaultHttpRequestFactory;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicHeader;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.handler.AbstractHandler;

/**
 * Uses system properties:
 *  - http.port for specifying the port
 *  - ntlm.user for specifying the expected username
 *  - ntlm.domain for specifying the expected domain
 */
public class NtlmProxy {

  public static void main(String[] args) throws Exception {
    int port = Integer.parseInt(System.getProperty("http.port", "8080"));

    Server server = new Server(port);
    server.setHandler(new AbstractHandler() {
      @Override
      public void handle(String s, Request request, HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws IOException {
        request.setHandled(true);
        NtlmProxy.service(httpServletRequest, httpServletResponse);
      }
    });
    server.start();
    server.join();
  }

  private static void service(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    String auth = getNtlmHeader(req);
    if (auth == null) {
      System.out.println("rejected; no ntlm");
      resp.addHeader("Connection", "close");
      resp.addHeader("Proxy-Authenticate", "NTLM");
      resp.sendError(407);
      return;
    }
    if (hasValidCredentials(auth)) {
      if (req.getMethod().equals("CONNECT")) {
        resp.sendError(405);
        return;
      }

      System.out.println("serving " + req.getMethod() + " " + req.getRequestURL());
      HttpRequest clone = cloneRequest(req);
      try (CloseableHttpClient client = HttpClients.createDefault()) {
        try (CloseableHttpResponse upstream = client.execute(getTarget(req), clone)) {
          resp.setStatus(upstream.getStatusLine().getStatusCode());
          for (Header header : upstream.getAllHeaders()) {
            resp.addHeader(header.getName(), header.getValue());
          }
          HttpEntity entity = upstream.getEntity();
          if (entity != null) {
            entity.writeTo(resp.getOutputStream());
          }
        }
      }
      return;
    }
    System.out.println("rejected; sending challenge");
    resp.addHeader("Connection", "keep-alive");
    resp.addHeader("Proxy-Authenticate", generateChallenge(auth));
    resp.sendError(407);
  }

  private static HttpHost getTarget(HttpServletRequest req) throws MalformedURLException {
    String originalUrl = req.getRequestURL().toString();
    URL host = new URL(originalUrl.substring(0, originalUrl.indexOf(req.getRequestURI())));
    return new HttpHost(host.getHost(), host.getPort(), host.getProtocol());
  }

  private static HttpRequest cloneRequest(HttpServletRequest req) throws IOException {
    HttpRequest clone;
    try {
      clone = DefaultHttpRequestFactory.INSTANCE.newHttpRequest(req.getMethod(), req.getRequestURI());
    }
    catch (MethodNotSupportedException e) {
      throw new RuntimeException(e);
    }

    List<Header> headers = new ArrayList<>();
    for (String name : Collections.list(req.getHeaderNames())) {
      if (name.equalsIgnoreCase("Proxy-Authenticate"))
        continue;
      for (String value : Collections.list(req.getHeaders(name))) {
        headers.add(new BasicHeader(name, value));
      }
    }
    clone.setHeaders(headers.toArray(new Header[0]));

    if (clone instanceof HttpEntityEnclosingRequest) {
      BasicHttpEntity entity = new BasicHttpEntity();
      entity.setContent(req.getInputStream());
      ((HttpEntityEnclosingRequest) clone).setEntity(entity);
    }

    return clone;
  }

  private static boolean hasValidCredentials(String header) {
    AuthenticateMessage authMessage = parseAuthenticate(Base64.getDecoder().decode(header.substring(5)));
    if (authMessage == null)
      return false;
    System.out.println(String.format(
        "accepted user=%s, domain=%s, workstation=%s",
        authMessage.userName, authMessage.domainName, authMessage.workstation));

    String expectedUser = System.getProperty("ntlm.user");
    String expectedDomain = System.getProperty("ntlm.domain");
    return (expectedUser == null || expectedUser.equalsIgnoreCase(authMessage.userName)) &&
        (expectedDomain == null || expectedDomain.equalsIgnoreCase(authMessage.domainName));
  }

  private static AuthenticateMessage parseAuthenticate(byte[] body) {
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

  private static String generateChallenge(String auth) throws IOException {
    NegotiateMessage negotiate = parseNegotiate(Base64.getDecoder().decode(auth.substring(5)));
    if (negotiate == null)
      return null;
    return "NTLM " + Base64.getEncoder().encodeToString(buildChallenge(new ChallengeMessage(null, null, 0)));
  }

  private static byte[] buildChallenge(ChallengeMessage challengeMessage) throws IOException {
    ByteBuffer dos = ByteBuffer.allocate(2048).order(ByteOrder.LITTLE_ENDIAN);

    byte[] targetName = (challengeMessage.targetName != null ? challengeMessage.targetName : "").getBytes(StandardCharsets.UTF_8);
    byte[] targetInfo = (challengeMessage.targetInfo != null ? challengeMessage.targetInfo : "").getBytes(StandardCharsets.UTF_8);

    ByteArrayOutputStream payload = new ByteArrayOutputStream();

    // signature
    dos.put(new byte[] {'N', 'T', 'L', 'M', 'S', 'S', 'P', 0});
    // MessageType
    dos.putInt(2);

    // TargetNameFields
    dos.putShort((short) targetName.length);
    dos.putShort((short) targetName.length);
    dos.putInt(56 + payload.size());
    payload.write(targetName);

    // NegotiateFlags
    dos.putInt(challengeMessage.flags);

    // ServerChallenge
    byte[] nonce = new byte[8];
    randomNextBytes(nonce);
    dos.put(nonce);

    // Reserved
    byte[] reserved = new byte[8];
    dos.put(reserved);

    // TargetInfoFields
    dos.putShort((short) targetInfo.length);
    dos.putShort((short) targetInfo.length);
    dos.putInt(56 + payload.size());
    payload.write(targetInfo);

    // Version
    byte[] version = new byte[8];
    dos.put(version);

    // Payload
    dos.put(payload.toByteArray());
    dos.flip();

    byte[] body = new byte[dos.limit()];
    dos.get(body);
    return body;
  }

  private static void randomNextBytes(byte[] nonce) {
    try {
      SecureRandom.getInstanceStrong().nextBytes(nonce);
    }
    catch (NoSuchAlgorithmException e) {
      throw new Error(e);
    }
  }

  private static NegotiateMessage parseNegotiate(byte[] message) {
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
    byte[] version = new byte[8];
    dis.get(version);

    byte[] payload = new byte[message.length - 40];
    dis.get(payload);

    String domainName = domainNameLen > 0 ? new String(payload, domainNameBufferOffset, domainNameLen) : null;
    String workstation = workstationLen > 0 ? new String(payload, workstationBufferOffset, workstationLen) : null;
    return new NegotiateMessage(domainName, workstation, negotiateFlags);
  }

  static class ChallengeMessage {

    public final String targetName;
    public final String targetInfo;
    public final int flags;

    ChallengeMessage(String targetName, String targetInfo, int flags) {
      this.targetName = targetName;
      this.targetInfo = targetInfo;
      this.flags = flags;
    }
  }

  static class NegotiateMessage {

    public final String domainName;
    public final String workstation;
    public final int flags;

    NegotiateMessage(String domainName, String workstation, int flags) {
      this.domainName = domainName;
      this.workstation = workstation;
      this.flags = flags;
    }
  }

  static class AuthenticateMessage {

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
  }

  private static String getNtlmHeader(HttpServletRequest req) {
    for (String s : Collections.list(req.getHeaders("Proxy-Authorization"))) {
      if (s.toLowerCase().startsWith("ntlm "))
        return s;
    }
    return null;
  }
}
