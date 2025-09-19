package tak.server.plugins.rhelidmcert.config;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.yaml.snakeyaml.Yaml;

/**
 * Plugin Configuration Class
 * 
 * Following TAK Server SDK pattern for YAML configuration:
 * - Configuration files located in /opt/tak/conf/plugins/
 * - File name is fully-qualified plugin class name + .yaml
 * - Auto-generates empty config file if not exists
 * - Supports default values and validation
 */
public class PluginConfiguration {
    
    private static final Logger logger = LoggerFactory.getLogger(PluginConfiguration.class);
    
    // Configuration file path (following SDK pattern)
    private static final String CONFIG_DIR = "/opt/tak/conf/plugins";
    private static final String CONFIG_FILE = "tak.server.plugins.rhelidmcert.RhelIdmCertificatePlugin.yaml";
    
    // Configuration sections
    private Map<String, Object> ldapConfig;
    private Map<String, Object> certificateConfig;
    private Map<String, Object> pluginConfig;
    
    // Default values
    private static final Map<String, Object> DEFAULT_LDAP_CONFIG = Map.of(
        "server_url", "ldaps://idm.example.com:636",
        "bind_dn", "uid=takserver,cn=users,cn=accounts,dc=example,dc=com",
        "bind_password", "changeme",
        "user_base_dn", "cn=users,cn=accounts,dc=example,dc=com",
        "group_base_dn", "cn=groups,cn=accounts,dc=example,dc=com",
        "required_group", "atak-users",
        "connection_timeout", 30,
        "use_ssl", true
    );
    
    private static final Map<String, Object> DEFAULT_CERTIFICATE_CONFIG = Map.of(
        "ca_cert_path", "/opt/tak/certs/ca.pem",
        "ca_key_path", "/opt/tak/certs/ca-key.pem",
        "ca_key_password", "",
        "validity_days", 365,
        "key_size", 2048,
        "signature_algorithm", "SHA256withRSA",
        "default_organization", "TAK Organization"
    );
    
    private static final Map<String, Object> DEFAULT_PLUGIN_CONFIG = Map.of(
        "log_level", "INFO",
        "enable_cot_notifications", true,
        "api_enabled", true,
        "max_concurrent_requests", 10
    );
    
    public PluginConfiguration() {
        // Initialize with defaults
        this.ldapConfig = new HashMap<>(DEFAULT_LDAP_CONFIG);
        this.certificateConfig = new HashMap<>(DEFAULT_CERTIFICATE_CONFIG);
        this.pluginConfig = new HashMap<>(DEFAULT_PLUGIN_CONFIG);
    }
    
    /**
     * Load configuration from YAML file
     * Following SDK pattern for plugin configuration loading
     */
    @SuppressWarnings("unchecked")
    public void loadConfiguration() {
        File configFile = new File(CONFIG_DIR, CONFIG_FILE);
        
        try {
            // Create config directory if it doesn't exist
            File configDir = new File(CONFIG_DIR);
            if (!configDir.exists()) {
                configDir.mkdirs();
            }
            
            // Create default config file if it doesn't exist
            if (!configFile.exists()) {
                createDefaultConfigFile(configFile);
                logger.info("Created default configuration file: {}", configFile.getAbsolutePath());
            }
            
            // Load configuration from file
            Yaml yaml = new Yaml();
            try (InputStream inputStream = new FileInputStream(configFile)) {
                Map<String, Object> config = yaml.load(inputStream);
                
                if (config != null) {
                    // Load sections with defaults
                    this.ldapConfig = mergeWithDefaults(
                        (Map<String, Object>) config.get("ldap"), DEFAULT_LDAP_CONFIG);
                    this.certificateConfig = mergeWithDefaults(
                        (Map<String, Object>) config.get("certificate"), DEFAULT_CERTIFICATE_CONFIG);
                    this.pluginConfig = mergeWithDefaults(
                        (Map<String, Object>) config.get("plugin"), DEFAULT_PLUGIN_CONFIG);
                }
            }
            
            logger.info("Configuration loaded successfully from: {}", configFile.getAbsolutePath());
            
        } catch (Exception e) {
            logger.error("Error loading configuration from {}: {}", configFile.getAbsolutePath(), e.getMessage());
            logger.warn("Using default configuration values");
        }
    }
    
    /**
     * Create default configuration file following SDK pattern
     */
    private void createDefaultConfigFile(File configFile) throws IOException {
        Map<String, Object> defaultConfig = Map.of(
            "ldap", DEFAULT_LDAP_CONFIG,
            "certificate", DEFAULT_CERTIFICATE_CONFIG,
            "plugin", DEFAULT_PLUGIN_CONFIG
        );
        
        Yaml yaml = new Yaml();
        try (FileWriter writer = new FileWriter(configFile)) {
            writer.write("# RHEL IDM Certificate Plugin Configuration\n");
            writer.write("# This file is auto-generated. Modify as needed.\n\n");
            yaml.dump(defaultConfig, writer);
        }
    }
    
    /**
     * Merge loaded config with defaults
     */
    private Map<String, Object> mergeWithDefaults(Map<String, Object> loaded, Map<String, Object> defaults) {
        Map<String, Object> merged = new HashMap<>(defaults);
        if (loaded != null) {
            merged.putAll(loaded);
        }
        return merged;
    }
    
    /**
     * Validate configuration
     */
    public boolean isValid() {
        try {
            // Validate required LDAP settings
            if (getLdapServerUrl() == null || getLdapServerUrl().trim().isEmpty()) {
                logger.error("LDAP server URL is required");
                return false;
            }
            
            if (getLdapBindDn() == null || getLdapBindDn().trim().isEmpty()) {
                logger.error("LDAP bind DN is required");
                return false;
            }
            
            // Validate certificate settings
            if (getCaCertPath() == null || getCaCertPath().trim().isEmpty()) {
                logger.error("CA certificate path is required");
                return false;
            }
            
            if (getCaKeyPath() == null || getCaKeyPath().trim().isEmpty()) {
                logger.error("CA private key path is required");
                return false;
            }
            
            // Validate file existence
            File caCert = new File(getCaCertPath());
            if (!caCert.exists() || !caCert.canRead()) {
                logger.error("CA certificate file not found or not readable: {}", getCaCertPath());
                return false;
            }
            
            File caKey = new File(getCaKeyPath());
            if (!caKey.exists() || !caKey.canRead()) {
                logger.error("CA private key file not found or not readable: {}", getCaKeyPath());
                return false;
            }
            
            return true;
            
        } catch (Exception e) {
            logger.error("Error validating configuration: {}", e.getMessage(), e);
            return false;
        }
    }
    
    // LDAP Configuration Getters
    public String getLdapServerUrl() {
        return (String) ldapConfig.get("server_url");
    }
    
    public String getLdapBindDn() {
        return (String) ldapConfig.get("bind_dn");
    }
    
    public String getLdapBindPassword() {
        return (String) ldapConfig.get("bind_password");
    }
    
    public String getUserBaseDn() {
        return (String) ldapConfig.get("user_base_dn");
    }
    
    public String getGroupBaseDn() {
        return (String) ldapConfig.get("group_base_dn");
    }
    
    public String getRequiredGroup() {
        return (String) ldapConfig.get("required_group");
    }
    
    public int getConnectionTimeout() {
        return (Integer) ldapConfig.get("connection_timeout");
    }
    
    public boolean isUseSsl() {
        return (Boolean) ldapConfig.get("use_ssl");
    }
    
    // Certificate Configuration Getters
    public String getCaCertPath() {
        return (String) certificateConfig.get("ca_cert_path");
    }
    
    public String getCaKeyPath() {
        return (String) certificateConfig.get("ca_key_path");
    }
    
    public String getCaKeyPassword() {
        return (String) certificateConfig.get("ca_key_password");
    }
    
    public int getCertificateValidityDays() {
        return (Integer) certificateConfig.get("validity_days");
    }
    
    public int getKeySize() {
        return (Integer) certificateConfig.get("key_size");
    }
    
    public String getSignatureAlgorithm() {
        return (String) certificateConfig.get("signature_algorithm");
    }
    
    public String getDefaultOrganization() {
        return (String) certificateConfig.get("default_organization");
    }
    
    // Plugin Configuration Getters
    public String getLogLevel() {
        return (String) pluginConfig.get("log_level");
    }
    
    public boolean isCotNotificationsEnabled() {
        return (Boolean) pluginConfig.get("enable_cot_notifications");
    }
    
    public boolean isApiEnabled() {
        return (Boolean) pluginConfig.get("api_enabled");
    }
    
    public int getMaxConcurrentRequests() {
        return (Integer) pluginConfig.get("max_concurrent_requests");
    }
    
    /**
     * Get configuration as Map for debugging/monitoring
     */
    public Map<String, Object> getConfigurationSummary() {
        Map<String, Object> summary = new HashMap<>();
        
        // Add non-sensitive LDAP config
        Map<String, Object> ldapSummary = new HashMap<>(ldapConfig);
        ldapSummary.put("bind_password", "***");  // Hide password
        summary.put("ldap", ldapSummary);
        
        // Add non-sensitive certificate config
        Map<String, Object> certSummary = new HashMap<>(certificateConfig);
        certSummary.put("ca_key_password", "***");  // Hide password
        summary.put("certificate", certSummary);
        
        // Add plugin config
        summary.put("plugin", pluginConfig);
        
        return summary;
    }
}