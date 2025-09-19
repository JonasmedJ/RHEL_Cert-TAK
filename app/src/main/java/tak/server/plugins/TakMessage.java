package tak.server.plugins;

// Simplified TAK Message representation
public class TakMessage {
    private String type;
    private String content;
    private AuthHeader authHeader;
    
    public String getType() { return type; }
    public void setType(String type) { this.type = type; }
    
    public String getContent() { return content; }
    public void setContent(String content) { this.content = content; }
    
    public AuthHeader getAuthHeader() { return authHeader; }
    public void setAuthHeader(AuthHeader authHeader) { this.authHeader = authHeader; }
    
    public boolean hasAuthHeader() { return authHeader != null; }
    
    public static class AuthHeader {
        private String username;
        public String getUsername() { return username; }
        public void setUsername(String username) { this.username = username; }
    }
}