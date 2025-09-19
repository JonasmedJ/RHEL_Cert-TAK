package tak.server.plugins.rhelidmcert.model;

/**
 * Certificate Request Model
 * 
 * Represents a certificate request for an already-authenticated TAK Server user.
 * The user has already been authenticated by TAK Server against LDAP/RHEL IDM.
 */
public class CertificateRequest {
    
    private String requestId;
    private String username;           // Already authenticated by TAK Server
    private String commonName;
    private String organization;
    private String organizationalUnit;
    private String country;
    private String email;
    private long timestamp;
    
    public CertificateRequest() {
        this.timestamp = System.currentTimeMillis();
    }
    
    // Getters and setters
    public String getRequestId() { return requestId; }
    public void setRequestId(String requestId) { this.requestId = requestId; }
    
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    
    public String getCommonName() { return commonName; }
    public void setCommonName(String commonName) { this.commonName = commonName; }
    
    public String getOrganization() { return organization; }
    public void setOrganization(String organization) { this.organization = organization; }
    
    public String getOrganizationalUnit() { return organizationalUnit; }
    public void setOrganizationalUnit(String organizationalUnit) { this.organizationalUnit = organizationalUnit; }
    
    public String getCountry() { return country; }
    public void setCountry(String country) { this.country = country; }
    
    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }
    
    public long getTimestamp() { return timestamp; }
    public void setTimestamp(long timestamp) { this.timestamp = timestamp; }
    
    @Override
    public String toString() {
        return String.format("CertificateRequest{requestId='%s', username='%s', commonName='%s', organization='%s'}", 
            requestId, username, commonName, organization);
    }
}