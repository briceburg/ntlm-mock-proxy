package red.sigil.proxy;

import java.io.IOException;
import java.util.EnumSet;

import javax.servlet.DispatcherType;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;

import org.eclipse.jetty.http.HttpHeader;
import org.eclipse.jetty.proxy.ConnectHandler;
import org.eclipse.jetty.proxy.ProxyServlet;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.handler.HandlerCollection;
import org.eclipse.jetty.servlet.FilterHolder;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;

public class NtlmServer {

  private static final String CONNECT_HEADER = HttpHeader.CONNECTION.asString();

  public static void main(String[] args) throws Exception {
    int port = Integer.parseInt(System.getProperty("http.port", "8080"));

    ServletContextHandler context = new ServletContextHandler();
    ServletHolder proxyServlet = new ServletHolder(ProxyServlet.class);
    context.addFilter(new FilterHolder(new NtlmServletFilter()), "/*", EnumSet.allOf(DispatcherType.class));
    context.addServlet(proxyServlet, "/*");

    HandlerCollection handlers = new HandlerCollection();
    handlers.addHandler(new NtlmConnectHandler());
    handlers.addHandler(context);

    Server server = new Server(port);
    server.setHandler(handlers);
    server.start();
    server.join();
  }

  static class NtlmServletFilter implements Filter {

    private final NtlmAuthentication ntlm = new NtlmAuthentication();

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
      HttpServletRequest httpRequest = (HttpServletRequest) request;
      HttpServletResponse httpResponse = (HttpServletResponse) response;
      if (!ntlm.handleAuthentication(httpRequest, httpResponse)) {
        System.out.println("non-connect handshaking ntlm: " + httpRequest.getRequestURL());
        httpResponse.sendError(HttpServletResponse.SC_PROXY_AUTHENTICATION_REQUIRED);
        return;
      }
      System.out.println("non-connect serving: " + httpRequest.getRequestURL());
      chain.doFilter(request, response);
    }

    @Override
    public void init(FilterConfig filterConfig) {
    }

    @Override
    public void destroy() {
    }
  }

  static class NtlmConnectHandler extends ConnectHandler {

    private final NtlmAuthentication ntlm = new NtlmAuthentication();

    @Override
    protected boolean handleAuthentication(HttpServletRequest request, HttpServletResponse response, String address) {
      try {
        if (!ntlm.handleAuthentication(request, response)) {
          System.out.println("connect handshaking ntlm: " + request.getRequestURI());
          return false;
        }
        System.out.println("connect serving: " + request.getRequestURI());
        return true;
      }
      catch (IOException e) {
        throw new RuntimeException(e);
      }
    }

    @Override
    protected void handleConnect(Request baseRequest, HttpServletRequest request, HttpServletResponse response, String serverAddress) {
      HttpServletResponseWrapper wrappedResponse = new HttpServletResponseWrapper(response) {
        @Override
        public void setHeader(String name, String value) {
          if (name.equalsIgnoreCase(CONNECT_HEADER) && containsHeader(CONNECT_HEADER))
            return; // dammit jetty, don't overwrite my headers!
          super.setHeader(name, value);
        }
      };
      super.handleConnect(baseRequest, request, wrappedResponse, serverAddress);
    }
  }

}
