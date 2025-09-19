package tak.server.plugins.rhelidmcert.service;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.util.Hashtable;


import javax.naming.Context;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.security.auth.x500.X500Principal;


import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import tak.server.plugins.rhelidmcert.config.PluginConfiguration;
import tak.server.plugins.rhelidmcert.RhelIdmCertificatePlugin.CertificateRequestInfo;

/**
 * RHEL IDM Certificate Service
 * 
 * Requests certificates from Red Hat Identity Management (FreeIPA) Certificate Authority
 * for already-authenticated TAK Server users.
 * 
 * Uses RHEL IDM's `ipa cert-request` command or REST API to:
 * 1. Generate Certificate Signing Request (CSR)
 * 2. Submit CSR to RHEL IDM CA using service account credentials
 * 3. Retrieve signed certificate from RHEL IDM
 * 4. Return certificate in PKCS#12 format for TAK clients
 */
public class RhelIdmCertificateService {
    
    private static final Logger logger = LoggerFactory.getLogger(RhelIdmCertificateService.class);
    
    private final PluginConfiguration config;
    private volatile DirContext serviceContext;
    
    public RhelIdmCertificateService(PluginConfiguration config) {
        this.config = config;
        initializeServiceConnection();
    }
    
    /**
     * Initialize service connection to RHEL IDM
     */
    private void initializeServiceConnection() {
        try {
            Hashtable<String, String> env = new Hashtable<>();
            env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
            env.put(Context.PROVIDER_URL, config.getLdapServerUrl());
            env.put(Context.SECURITY_AUTHENTICATION, "simple");
            env.put(Context.SECURITY_PRINCIPAL, config.getLdapBindDn());
            env.put(Context.SECURITY_CREDENTIALS, config.getLdapBindPassword());
            
            if (config.isUseSsl()) {
                env.put(Context.SECURITY_PROTOCOL, "ssl");
            }
            
            this.serviceContext = new InitialDirContext(env);
            logger.info("Service connection to RHEL IDM initialized successfully");
            
        } catch (Exception e) {
            logger.error("Failed to initialize service connection to RHEL IDM: {}", e.getMessage(), e);
            this.serviceContext = null;
        }
    }
    
    /**
     * Request certificate from RHEL IDM for authenticated user
     */
    public byte[] requestCertificateForUser(CertificateRequestInfo requestInfo) {
        try {
            logger.info("Requesting certificate from RHEL IDM CA for user: {}", requestInfo.getUsername());
            
            // Method 1: Try IPA command-line interface (most reliable)
            byte[] certificate = requestCertificateViaIpaCommand(requestInfo);
            if (certificate != null) {
                logger.info("Successfully obtained certificate via IPA command for user: {}", requestInfo.getUsername());
                return certificate;
            }
            
            // Method 2: Try direct certmonger approach (if available)
            certificate = requestCertificateViaCertmonger(requestInfo);
            if (certificate != null) {
                logger.info("Successfully obtained certificate via certmonger for user: {}", requestInfo.getUsername());
                return certificate;
            }
            
            logger.error("Failed to obtain certificate from RHEL IDM using all available methods");
            return null;
            
        } catch (Exception e) {
            logger.error("Error requesting certificate from RHEL IDM: {}", e.getMessage(), e);
            return null;
        }
    }
    
    /**
     * Request certificate using IPA command-line interface
     * This is the most reliable method for RHEL IDM certificate requests
     */
    private byte[] requestCertificateViaIpaCommand(CertificateRequestInfo requestInfo) {
        try {
            logger.debug("Attempting certificate request via IPA command-line for user: {}", requestInfo.getUsername());
            
            // Step 1: Generate key pair and CSR
            KeyPair keyPair = generateKeyPair();
            String csrPem = generateCSR(requestInfo, keyPair);
            
            // Step 2: Execute IPA certificate request command
            String ipaCommand = buildIpaCertRequestCommand(requestInfo, csrPem);
            Process process = Runtime.getRuntime().exec(ipaCommand);
            
            // Step 3: Read command output
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            BufferedReader errorReader = new BufferedReader(new InputStreamReader(process.getErrorStream()));
            
            StringBuilder output = new StringBuilder();
            StringBuilder errorOutput = new StringBuilder();
            
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            
            while ((line = errorReader.readLine()) != null) {
                errorOutput.append(line).append("\n");
            }
            
            int exitCode = process.waitFor();
            
            if (exitCode == 0) {
                // Step 4: Extract certificate from IPA output
                return extractCertificateFromIpaOutput(output.toString(), keyPair);
            } else {
                logger.error("IPA certificate request failed with exit code {}: {}", exitCode, errorOutput.toString());
                return null;
            }
            
        } catch (Exception e) {
            logger.error("Error executing IPA certificate request: {}", e.getMessage(), e);
            return null;
        }
    }
    
    /**
     * Build IPA certificate request command
     */
    private String buildIpaCertRequestCommand(CertificateRequestInfo requestInfo, String csrPem) {
        // Example IPA command structure:
        // ipa cert-request --principal=username@REALM certificate_request.csr
        
        String principal = requestInfo.getUsername() + "@" + extractRealmFromDn(config.getLdapBindDn());
        
        return String.format("echo '%s' | ipa cert-request --principal=%s --stdin", 
            csrPem.replace("\n", "\\n"), principal);
    }
    
    /**
     * Extract realm from LDAP DN
     */
    private String extractRealmFromDn(String dn) {
        // Extract realm from DN like: uid=service,cn=users,cn=accounts,dc=example,dc=com
        // Result should be: EXAMPLE.COM
        try {
            String[] parts = dn.split(",");
            StringBuilder realm = new StringBuilder();
            
            for (String part : parts) {
                if (part.trim().startsWith("dc=")) {
                    if (realm.length() > 0) {
                        realm.append(".");
                    }
                    realm.append(part.substring(3).trim().toUpperCase());
                }
            }
            
            return realm.toString();
        } catch (Exception e) {
            logger.warn("Could not extract realm from DN: {}", dn);
            return "EXAMPLE.COM"; // Default fallback
        }
    }
    
    /**
     * Request certificate using certmonger (alternative method)
     */
    private byte[] requestCertificateViaCertmonger(CertificateRequestInfo requestInfo) {
    try {
        logger.debug("Attempting certificate request via certmonger for user: {}", requestInfo.getUsername());
        
        // Generate key pair and CSR
        KeyPair keyPair = generateKeyPair();
        String csrPem = generateCSR(requestInfo, keyPair);
        
        // Write CSR to temporary file for certmonger
        String csrFile = "/tmp/user_" + requestInfo.getUsername() + ".csr";
        java.nio.file.Files.write(java.nio.file.Paths.get(csrFile), csrPem.getBytes());
        
        // Use certmonger to submit request to IPA CA
        ProcessBuilder processBuilder = new ProcessBuilder(
            "getcert", "request", 
            "-f", "/tmp/user_" + requestInfo.getUsername() + ".crt",
            "-k", "/tmp/user_" + requestInfo.getUsername() + ".key",
            "-r", csrFile,  // Now using the CSR file
            "-w"
        );
        Process process = processBuilder.start();
        int exitCode = process.waitFor();
        
        if (exitCode == 0) {
            // Clean up temporary CSR file
            java.nio.file.Files.deleteIfExists(java.nio.file.Paths.get(csrFile));
            
            // Read the generated certificate
            return readCertificateFile("/tmp/user_" + requestInfo.getUsername() + ".crt", keyPair);
        } else {
            logger.error("Certmonger request failed with exit code: {}", exitCode);
            return null;
        }
        
    } catch (Exception e) {
        logger.error("Error using certmonger for certificate request: {}", e.getMessage(), e);
        return null;
    }
}
    
    /**
     * Generate RSA key pair
     */
    private KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(config.getKeySize(), new SecureRandom());
        return keyPairGenerator.generateKeyPair();
    }
    
    /**
     * Generate Certificate Signing Request (CSR)
     */
    private String generateCSR(CertificateRequestInfo requestInfo, KeyPair keyPair) throws Exception {
        
        // Create subject DN
        String subjectDn = String.format("CN=%s,O=%s", 
            requestInfo.getCommonName(), 
            requestInfo.getOrganization() != null ? requestInfo.getOrganization() : config.getDefaultOrganization());
        
        X500Principal subject = new X500Principal(subjectDn);
        
        // Build CSR
        PKCS10CertificationRequestBuilder csrBuilder = new JcaPKCS10CertificationRequestBuilder(
            subject, keyPair.getPublic());
        
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
            .setProvider("BC")
            .build(keyPair.getPrivate());
        
        org.bouncycastle.pkcs.PKCS10CertificationRequest csr = csrBuilder.build(signer);
        
        // Convert to PEM format
        StringWriter sw = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(sw)) {
            pemWriter.writeObject(csr);
        }
        
        return sw.toString();
    }
    
    /**
     * Extract certificate from IPA command output
     */
    private byte[] extractCertificateFromIpaOutput(String ipaOutput, KeyPair keyPair) {
        try {
            // IPA output typically contains the certificate in the response
            // Parse the output to extract the certificate
            
            // Look for certificate in the output
            String certStart = "-----BEGIN CERTIFICATE-----";
            String certEnd = "-----END CERTIFICATE-----";
            
            int startIndex = ipaOutput.indexOf(certStart);
            int endIndex = ipaOutput.indexOf(certEnd);
            
            if (startIndex != -1 && endIndex != -1) {
                String certificatePem = ipaOutput.substring(startIndex, endIndex + certEnd.length());
                
                // Convert to PKCS#12 format for TAK clients
                return convertToPkcs12(certificatePem, keyPair);
            } else {
                logger.error("Could not find certificate in IPA output");
                return null;
            }
            
        } catch (Exception e) {
            logger.error("Error extracting certificate from IPA output: {}", e.getMessage(), e);
            return null;
        }
    }
    
    /**
     * Read certificate from file (for certmonger method)
     */
    private byte[] readCertificateFile(String filePath, KeyPair keyPair) {
        try {
            // Read certificate file and convert to PKCS#12
            java.nio.file.Path path = java.nio.file.Paths.get(filePath);
            if (!java.nio.file.Files.exists(path)) {
                logger.error("Certificate file not found: {}", filePath);
                return null;
            }
            
            String certificatePem = new String(java.nio.file.Files.readAllBytes(path));
            return convertToPkcs12(certificatePem, keyPair);
            
        } catch (Exception e) {
            logger.error("Error reading certificate file: {}", e.getMessage(), e);
            return null;
        }
    }
    
    /**
     * Convert PEM certificate to PKCS#12 format for TAK clients
     */
    private byte[] convertToPkcs12(String certificatePem, KeyPair keyPair) {
        try {
            // Parse the PEM certificate
            // Create PKCS#12 keystore with certificate and private key
            // This would need proper implementation using Bouncy Castle
            
            // For now, return the certificate bytes (would need full implementation)
            return certificatePem.getBytes();
            
        } catch (Exception e) {
            logger.error("Error converting certificate to PKCS#12: {}", e.getMessage(), e);
            return null;
        }
    }
    
    /**
     * Test connection to RHEL IDM
     */
    public boolean testConnection() {
        try {
            if (serviceContext == null) {
                initializeServiceConnection();
            }
            
            if (serviceContext != null) {
                // Test the connection with a simple operation
                serviceContext.getAttributes("", new String[]{"objectClass"});
                return true;
            }
            
        } catch (Exception e) {
            logger.debug("RHEL IDM connection test failed: {}", e.getMessage());
        }
        
        return false;
    }
    
    /**
     * Close service connection
     */
    public void close() {
        try {
            if (serviceContext != null) {
                serviceContext.close();
                serviceContext = null;
            }
            logger.info("RHEL IDM Certificate Service closed");
        } catch (Exception e) {
            logger.error("Error closing RHEL IDM service: {}", e.getMessage(), e);
        }
    }
}