# Purpose

NTLM proxy that does not check passwords.
Useful for testing NTLM proxy support.
Tested to work with Apache HttpClient.

# Running 

```
mvn clean package
java -jar target/ntlm-mock-proxy.jar
```

# Configure with system properties

 - http.port - proxy http port (default 8080)
 - ntlm.user - expected username (default - don't check)             
 - ntlm.domain - expected domain (default - don't check)
