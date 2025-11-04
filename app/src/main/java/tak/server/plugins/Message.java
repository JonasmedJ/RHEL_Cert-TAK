package tak.server.plugins;

/**
 * Represents a message in the TAK Server system.
 *
 * This is a simplified representation of TAK Server messages.
 * In the real TAK Server, this would be a more complex class
 * with protocol buffer support and additional metadata.
 */
public class Message {
    private String type;
    private String content;
    private byte[] payload;
    private AuthHeader authHeader;

    public Message() {
    }

    public Message(String type, String content) {
        this.type = type;
        this.content = content;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getContent() {
        return content;
    }

    public void setContent(String content) {
        this.content = content;
    }

    public byte[] getPayload() {
        return payload;
    }

    public void setPayload(byte[] payload) {
        this.payload = payload;
    }

    public AuthHeader getAuthHeader() {
        return authHeader;
    }

    public void setAuthHeader(AuthHeader authHeader) {
        this.authHeader = authHeader;
    }

    public boolean hasAuthHeader() {
        return authHeader != null;
    }

    /**
     * Authentication header containing user information
     */
    public static class AuthHeader {
        private String username;
        private String[] roles;

        public String getUsername() {
            return username;
        }

        public void setUsername(String username) {
            this.username = username;
        }

        public String[] getRoles() {
            return roles;
        }

        public void setRoles(String[] roles) {
            this.roles = roles;
        }
    }
}
