package tak.server.plugins.rhelidmcert;

import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import tak.server.plugins.MessageInterceptorBase;
import tak.server.plugins.SubmitDataPlugin;
import tak.server.plugins.PluginInfo;
import tak.server.plugins.PluginManager;
import tak.server.plugins.TakMessage;

import tak.server.plugins.rhelidmcert.config.PluginConfiguration;
import tak.server.plugins.rhelidmcert.service.RhelIdmCertificateService;

/**
 * RHEL IDM Certificate Plugin for TAK Server
 * 
 * CORRECT WORKFLOW:
 * 1. ATAK client → username/password → TAK Server
 * 2. TAK Server → authenticate → LDAP/RHEL IDM  
 * 3. LDAP/RHEL IDM → auth success → TAK Server
 * 4. Plugin intercepts certificate request and forwards to RHEL IDM
 * 5. RHEL IDM → certificate → Plugin → TAK Server
 * 6. TAK Server → certificate → ATAK client
 * 
 * This plugin:
 * - Intercepts TAK Server's certificate generation messages
 * - Uses already-authenticated user information from TAK Server
 * - Requests certificates from RHEL IDM CA (not generates locally)
 * - Returns RHEL IDM certificates to TAK Server flow
 */
public class RhelIdmCertificatePlugin extends MessageInterceptorBase implements SubmitDataPlugin {
    
    private static final Logger logger = LoggerFactory.getLogger(RhelIdmCertificatePlugin.class);
    
    // Plugin metadata
    private static final String PLUGIN_NAME = "RHEL IDM Certificate Plugin";
    private static final String PLUGIN_VERSION = "1.0.0";
    private static final String PLUGIN_DESCRIPTION = "Intercepts TAK Server certificate generation and uses RHEL IDM CA";
    
    // Services
    private PluginConfiguration config;
    private RhelIdmCertificateService rhelidmService;
    private PluginManager pluginManager;
    
    /**
     * Plugin lifecycle - called when plugin is loaded
     */
    @Override
    public void onPluginLoaded(PluginManager pluginManager) {
        try {
            logger.info("Loading {} v{}", PLUGIN_NAME, PLUGIN_VERSION);
            
            this.pluginManager = pluginManager;
            
            // Initialize configuration
            config = new PluginConfiguration();
            config.loadConfiguration();
            
            // Initialize RHEL IDM service (uses service account, not user auth)
            rhelidmService = new RhelIdmCertificateService(config);
            
            // Test connection to RHEL IDM
            if (rhelidmService.testConnection()) {
                logger.info("Successfully connected to RHEL IDM: {}", config.getLdapServerUrl());
            } else {
                logger.error("Failed to connect to RHEL IDM - certificate requests will fail");
            }
            
            logger.info("{} loaded successfully - will intercept certificate generation", PLUGIN_NAME);
            
        } catch (Exception e) {
            logger.error("Failed to load {}: {}", PLUGIN_NAME, e.getMessage(), e);
            throw new RuntimeException("Plugin load failed", e);
        }
    }
    
    /**
     * Plugin lifecycle - called when plugin is unloaded
     */
    @Override
    public void onPluginUnloaded() {
        try {
            logger.info("Unloading {}", PLUGIN_NAME);
            
            if (rhelidmService != null) {
                rhelidmService.close();
            }
            
            logger.info("{} unloaded successfully", PLUGIN_NAME);
            
        } catch (Exception e) {
            logger.error("Error during plugin unload: {}", e.getMessage(), e);
        }
    }
    
    /**
     * Message interceptor - intercepts TAK Server certificate generation
     * 
     * This is where we intercept the certificate request in TAK Server's flow
     * and replace the certificate generation with RHEL IDM certificate request
     */
    @Override
    public Object intercept(Object message) {
        try {
            if (!(message instanceof TakMessage)) {
                return message;
            }
            
            TakMessage takMessage = (TakMessage) message;
            
            // Check if this is a certificate generation request from TAK Server
            if (isCertificateGenerationRequest(takMessage)) {
                logger.debug("Intercepting certificate generation request for user: {}", 
                    getUsernameFromMessage(takMessage));
                
                // Replace TAK Server's certificate with RHEL IDM certificate
                return handleCertificateGeneration(takMessage);
            }
            
            // Pass through all other messages unchanged
            return message;
            
        } catch (Exception e) {
            logger.error("Error intercepting message: {}", e.getMessage(), e);
            return message; // Return original message on error
        }
    }
    
    /**
     * Handle certificate generation by requesting from RHEL IDM
     */
    private Object handleCertificateGeneration(TakMessage originalMessage) {
        try {
            String username = getUsernameFromMessage(originalMessage);
            if (username == null) {
                logger.error("Cannot extract username from certificate request");
                return originalMessage;
            }
            
            logger.info("Requesting certificate from RHEL IDM for authenticated user: {}", username);
            
            // Create certificate request for RHEL IDM
            CertificateRequestInfo requestInfo = new CertificateRequestInfo();
            requestInfo.setUsername(username);
            requestInfo.setCommonName(username);
            requestInfo.setOrganization(config.getDefaultOrganization());
            
            // Request certificate from RHEL IDM
            byte[] rhelidmCertificate = rhelidmService.requestCertificateForUser(requestInfo);
            
            if (rhelidmCertificate != null) {
                // Create modified message with RHEL IDM certificate
                TakMessage modifiedMessage = createCertificateResponseMessage(originalMessage, rhelidmCertificate);
                logger.info("Successfully obtained certificate from RHEL IDM for user: {}", username);
                return modifiedMessage;
            } else {
                logger.error("Failed to obtain certificate from RHEL IDM for user: {}", username);
                return originalMessage; // Fall back to original TAK Server behavior
            }
            
        } catch (Exception e) {
            logger.error("Error handling certificate generation: {}", e.getMessage(), e);
            return originalMessage; // Fall back to original TAK Server behavior
        }
    }
    
    /**
     * Submit data plugin interface for direct API access
     */
    @Override
    public Object onSubmitData(String pathVariable, Map<String, String[]> allRequestParams) {
        try {
            logger.debug("Received API request for path: {}", pathVariable);
            
            switch (pathVariable) {
                case "status":
                    return getPluginStatus();
                    
                case "test":
                    return testRhelIdmConnection();
                    
                case "request-cert":
                    return handleDirectCertificateRequest(allRequestParams);
                    
                default:
                    return Map.of("error", "Unknown endpoint: " + pathVariable);
            }
            
        } catch (Exception e) {
            logger.error("Error processing API request: {}", e.getMessage(), e);
            return Map.of("error", "Internal error: " + e.getMessage());
        }
    }
    
    /**
     * Handle direct certificate request via API (for testing/manual requests)
     */
    private Object handleDirectCertificateRequest(Map<String, String[]> params) {
        try {
            String username = getFirstParam(params, "username");
            if (username == null) {
                return Map.of("error", "Username parameter required");
            }
            
            // NOTE: This is for testing only - in production, users should be 
            // authenticated through TAK Server's normal flow
            logger.info("Direct certificate request for user: {}", username);
            
            CertificateRequestInfo requestInfo = new CertificateRequestInfo();
            requestInfo.setUsername(username);
            requestInfo.setCommonName(username);
            requestInfo.setOrganization(config.getDefaultOrganization());
            
            byte[] certificate = rhelidmService.requestCertificateForUser(requestInfo);
            
            if (certificate != null) {
                return Map.of(
                    "success", true,
                    "message", "Certificate obtained from RHEL IDM",
                    "certificateSize", certificate.length
                );
            } else {
                return Map.of("error", "Failed to obtain certificate from RHEL IDM");
            }
            
        } catch (Exception e) {
            logger.error("Error handling direct certificate request: {}", e.getMessage(), e);
            return Map.of("error", "Request failed: " + e.getMessage());
        }
    }
    
    /**
     * Check if message is a certificate generation request from TAK Server
     */
    private boolean isCertificateGenerationRequest(TakMessage message) {
        if (message.getType() == null) {
            return false;
        }
        
        String type = message.getType().toLowerCase();
        return type.contains("cert") && 
               (type.contains("generate") || type.contains("request") || type.contains("enroll"));
    }
    
    /**
     * Extract username from TAK message
     */
    private String getUsernameFromMessage(TakMessage message) {
        // Extract username from authenticated user context in TAK Server
        if (message.hasAuthHeader()) {
            return message.getAuthHeader().getUsername();
        }
        
        // Could also extract from message content if needed
        return null;
    }
    
    /**
     * Create certificate response message with RHEL IDM certificate
     */
    private TakMessage createCertificateResponseMessage(TakMessage originalMessage, byte[] certificate) {
        // Create a modified message containing the RHEL IDM certificate
        // This would need to match TAK Server's expected certificate message format
        
        TakMessage responseMessage = new TakMessage();
        responseMessage.setType("certificate-response");
        
        // Set certificate data in appropriate format for TAK Server
        // This format would need to match what TAK Server expects
        String certificateB64 = java.util.Base64.getEncoder().encodeToString(certificate);
        responseMessage.setContent(certificateB64);
        
        // Copy auth header from original message
        if (originalMessage.hasAuthHeader()) {
            responseMessage.setAuthHeader(originalMessage.getAuthHeader());
        }
        
        return responseMessage;
    }
    
    /**
     * Get plugin status
     */
    private Object getPluginStatus() {
        return Map.of(
            "plugin", PLUGIN_NAME,
            "version", PLUGIN_VERSION,
            "status", "running",
            "rhelidmConnected", rhelidmService != null && rhelidmService.testConnection(),
            "rhelidmServer", config.getLdapServerUrl()
        );
    }
    
    /**
     * Test RHEL IDM connection
     */
    private Object testRhelIdmConnection() {
        boolean connected = rhelidmService != null && rhelidmService.testConnection();
        return Map.of(
            "rhelidmConnected", connected,
            "rhelidmServer", config.getLdapServerUrl(),
            "message", connected ? "Connection successful" : "Connection failed"
        );
    }
    
    /**
     * Helper method to get first parameter value
     */
    private String getFirstParam(Map<String, String[]> params, String key) {
        String[] values = params.get(key);
        return (values != null && values.length > 0) ? values[0] : null;
    }
    
    /**
     * Plugin info for TAK Server
     */
    @Override
    public PluginInfo getPluginInfo() {
        return PluginInfo.builder()
            .name(PLUGIN_NAME)
            .version(PLUGIN_VERSION)
            .description(PLUGIN_DESCRIPTION)
            .build();
    }
    
    /**
     * Certificate request info class
     */
    public static class CertificateRequestInfo {
        private String username;
        private String commonName;
        private String organization;
        
        public String getUsername() { return username; }
        public void setUsername(String username) { this.username = username; }
        
        public String getCommonName() { return commonName; }
        public void setCommonName(String commonName) { this.commonName = commonName; }
        
        public String getOrganization() { return organization; }
        public void setOrganization(String organization) { this.organization = organization; }
    }
}