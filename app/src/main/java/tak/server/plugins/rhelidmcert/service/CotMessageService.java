package tak.server.plugins.rhelidmcert.service;

import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import tak.server.plugins.PluginManager;
import tak.server.plugins.TakMessage;
import tak.server.plugins.rhelidmcert.model.CertificateResponse;

/**
 * Cursor-on-Target (CoT) Message Service
 * 
 * Handles sending TAK protocol messages for certificate enrollment notifications.
 * Sends notifications to other connected TAK clients when certificates are issued.
 */
public class CotMessageService {
    
    private static final Logger logger = LoggerFactory.getLogger(CotMessageService.class);
    
    private final PluginManager pluginManager;
    
    public CotMessageService(PluginManager pluginManager) {
        this.pluginManager = pluginManager;
    }
    
    /**
     * Send certificate enrollment notification to TAK clients
     */
    public void sendCertificateEnrollmentNotification(String username) {
        try {
            logger.debug("Sending certificate enrollment notification for user: {}", username);
            
            // Create CoT message for certificate enrollment
            TakMessage notification = createCertificateEnrollmentMessage(username);
            
            // Send message via plugin manager to all connected clients
            if (pluginManager != null) {
                pluginManager.sendMessage(notification);
                logger.debug("Certificate enrollment notification sent for user: {}", username);
            } else {
                logger.warn("Plugin manager not available - cannot send notification");
            }
            
        } catch (Exception e) {
            logger.error("Error sending certificate enrollment notification: {}", e.getMessage(), e);
        }
    }
    
    /**
     * Send certificate response back to requesting client
     */
    public void sendCertificateResponseToClient(TakMessage originalMessage, CertificateResponse response) {
        try {
            logger.debug("Sending certificate response to client");
            
            // Create response message
            TakMessage responseMessage = createCertificateResponseMessage(originalMessage, response);
            
            // Send response back to requesting client
            if (pluginManager != null) {
                pluginManager.sendMessage(responseMessage);
                logger.debug("Certificate response sent to client");
            } else {
                logger.warn("Plugin manager not available - cannot send response");
            }
            
        } catch (Exception e) {
            logger.error("Error sending certificate response to client: {}", e.getMessage(), e);
        }
    }
    
    /**
     * Create CoT message for certificate enrollment notification
     */
    private TakMessage createCertificateEnrollmentMessage(String username) {
        TakMessage message = new TakMessage();
        
        // Set message type
        message.setType("certificate-enrollment-notification");
        
        // Create CoT XML content for certificate enrollment
        String cotXml = createCertificateEnrollmentCoT(username);
        message.setContent(cotXml);
        
        return message;
    }
    
    /**
     * Create certificate response message
     */
    private TakMessage createCertificateResponseMessage(TakMessage originalMessage, CertificateResponse response) {
        TakMessage responseMessage = new TakMessage();
        
        // Set response type
        responseMessage.setType("certificate-response");
        
        // Copy auth header from original message
        if (originalMessage.hasAuthHeader()) {
            responseMessage.setAuthHeader(originalMessage.getAuthHeader());
        }
        
        // Create response content
        if (response.isSuccess()) {
            // Encode certificate data as base64
            String certificateB64 = java.util.Base64.getEncoder().encodeToString(response.getCertificateData());
            String responseXml = createCertificateResponseCoT(certificateB64, response);
            responseMessage.setContent(responseXml);
        } else {
            // Create error response
            String errorXml = createCertificateErrorCoT(response.getMessage());
            responseMessage.setContent(errorXml);
        }
        
        return responseMessage;
    }
    
    /**
     * Create CoT XML for certificate enrollment notification
     */
    private String createCertificateEnrollmentCoT(String username) {
        long timestamp = System.currentTimeMillis();
        String uid = UUID.randomUUID().toString();
        
        return String.format(
            "<?xml version='1.0' encoding='UTF-8' standalone='yes'?>" +
            "<event version='2.0' uid='%s' type='a-f-G-U-C' time='%s' start='%s' stale='%s' how='h-e'>" +
            "<point lat='0.0' lon='0.0' hae='0.0' ce='999999.0' le='999999.0'/>" +
            "<detail>" +
            "<contact callsign='RHEL-IDM-CA'/>" +
            "<remarks>Certificate enrolled for user: %s via RHEL IDM</remarks>" +
            "<certificate-enrollment>" +
            "<username>%s</username>" +
            "<timestamp>%d</timestamp>" +
            "<source>RHEL-IDM</source>" +
            "</certificate-enrollment>" +
            "</detail>" +
            "</event>",
            uid,
            formatCoTTime(timestamp),
            formatCoTTime(timestamp),
            formatCoTTime(timestamp + 300000), // Stale in 5 minutes
            username,
            username,
            timestamp
        );
    }
    
    /**
     * Create CoT XML for certificate response
     */
    private String createCertificateResponseCoT(String certificateB64, CertificateResponse response) {
        long timestamp = System.currentTimeMillis();
        String uid = UUID.randomUUID().toString();
        
        return String.format(
            "<?xml version='1.0' encoding='UTF-8' standalone='yes'?>" +
            "<event version='2.0' uid='%s' type='a-f-G-U-C' time='%s' start='%s' stale='%s' how='h-e'>" +
            "<point lat='0.0' lon='0.0' hae='0.0' ce='999999.0' le='999999.0'/>" +
            "<detail>" +
            "<contact callsign='RHEL-IDM-CA'/>" +
            "<remarks>Certificate response from RHEL IDM</remarks>" +
            "<certificate-response>" +
            "<success>%s</success>" +
            "<format>%s</format>" +
            "<certificate>%s</certificate>" +
            "<timestamp>%d</timestamp>" +
            "</certificate-response>" +
            "</detail>" +
            "</event>",
            uid,
            formatCoTTime(timestamp),
            formatCoTTime(timestamp),
            formatCoTTime(timestamp + 60000), // Stale in 1 minute
            response.isSuccess(),
            response.getCertificateFormat(),
            certificateB64,
            timestamp
        );
    }
    
    /**
     * Create CoT XML for certificate error
     */
    private String createCertificateErrorCoT(String errorMessage) {
        long timestamp = System.currentTimeMillis();
        String uid = UUID.randomUUID().toString();
        
        return String.format(
            "<?xml version='1.0' encoding='UTF-8' standalone='yes'?>" +
            "<event version='2.0' uid='%s' type='a-f-G-E-A' time='%s' start='%s' stale='%s' how='h-e'>" +
            "<point lat='0.0' lon='0.0' hae='0.0' ce='999999.0' le='999999.0'/>" +
            "<detail>" +
            "<contact callsign='RHEL-IDM-CA'/>" +
            "<remarks>Certificate request error</remarks>" +
            "<certificate-error>" +
            "<message>%s</message>" +
            "<timestamp>%d</timestamp>" +
            "</certificate-error>" +
            "</detail>" +
            "</event>",
            uid,
            formatCoTTime(timestamp),
            formatCoTTime(timestamp),
            formatCoTTime(timestamp + 60000), // Stale in 1 minute
            errorMessage,
            timestamp
        );
    }
    
    /**
     * Format timestamp for CoT XML
     */
    private String formatCoTTime(long timestamp) {
        return java.time.Instant.ofEpochMilli(timestamp).toString();
    }
    
    /**
     * Send custom CoT message
     */
    public void sendCustomCoTMessage(String cotXml) {
        try {
            if (pluginManager != null) {
                TakMessage message = new TakMessage();
                message.setType("custom-cot");
                message.setContent(cotXml);
                
                pluginManager.sendMessage(message);
                logger.debug("Custom CoT message sent");
            }
        } catch (Exception e) {
            logger.error("Error sending custom CoT message: {}", e.getMessage(), e);
        }
    }
    
    /**
     * Send status message to TAK clients
     */
    public void sendStatusMessage(String status, String details) {
        try {
            long timestamp = System.currentTimeMillis();
            String uid = UUID.randomUUID().toString();
            
            String statusCoT = String.format(
                "<?xml version='1.0' encoding='UTF-8' standalone='yes'?>" +
                "<event version='2.0' uid='%s' type='a-f-G-I-M' time='%s' start='%s' stale='%s' how='h-e'>" +
                "<point lat='0.0' lon='0.0' hae='0.0' ce='999999.0' le='999999.0'/>" +
                "<detail>" +
                "<contact callsign='RHEL-IDM-Plugin'/>" +
                "<remarks>RHEL IDM Certificate Plugin Status: %s</remarks>" +
                "<plugin-status>" +
                "<status>%s</status>" +
                "<details>%s</details>" +
                "<timestamp>%d</timestamp>" +
                "</plugin-status>" +
                "</detail>" +
                "</event>",
                uid,
                formatCoTTime(timestamp),
                formatCoTTime(timestamp),
                formatCoTTime(timestamp + 120000), // Stale in 2 minutes
                status,
                status,
                details,
                timestamp
            );
            
            sendCustomCoTMessage(statusCoT);
            
        } catch (Exception e) {
            logger.error("Error sending status message: {}", e.getMessage(), e);
        }
    }
}