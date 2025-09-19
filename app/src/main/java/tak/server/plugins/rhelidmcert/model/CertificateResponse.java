package tak.server.plugins.rhelidmcert.model;

/**
 * Certificate Response Model
 * 
 * Represents the response from RHEL IDM certificate request.
 */
public class CertificateResponse {
    
    private boolean success;
    private String message;
    private String requestId;
    private byte[] certificateData;
    private String certificateFormat;
    private long timestamp;
    private String errorCode;
    
    public CertificateResponse() {
        this.timestamp = System.currentTimeMillis();
    }
    
    // Static factory methods
    public static CertificateResponse success(byte[] certificateData) {
        CertificateResponse response = new CertificateResponse();
        response.success = true;
        response.certificateData = certificateData;
        response.certificateFormat = "PKCS12";
        response.message = "Certificate generated successfully";
        return response;
    }
    
    public static CertificateResponse success(byte[] certificateData, String requestId) {
        CertificateResponse response = success(certificateData);
        response.requestId = requestId;
        return response;
    }
    
    public static CertificateResponse error(String message) {
        CertificateResponse response = new CertificateResponse();
        response.success = false;
        response.message = message;
        return response;
    }
    
    public static CertificateResponse error(String message, String errorCode) {
        CertificateResponse response = error(message);
        response.errorCode = errorCode;
        return response;
    }
    
    // Getters and setters
    public boolean isSuccess() { return success; }
    public void setSuccess(boolean success) { this.success = success; }
    
    public String getMessage() { return message; }
    public void setMessage(String message) { this.message = message; }
    
    public String getRequestId() { return requestId; }
    public void setRequestId(String requestId) { this.requestId = requestId; }
    
    public byte[] getCertificateData() { return certificateData; }
    public void setCertificateData(byte[] certificateData) { this.certificateData = certificateData; }
    
    public String getCertificateFormat() { return certificateFormat; }
    public void setCertificateFormat(String certificateFormat) { this.certificateFormat = certificateFormat; }
    
    public long getTimestamp() { return timestamp; }
    public void setTimestamp(long timestamp) { this.timestamp = timestamp; }
    
    public String getErrorCode() { return errorCode; }
    public void setErrorCode(String errorCode) { this.errorCode = errorCode; }
    
    @Override
    public String toString() {
        return String.format("CertificateResponse{success=%s, requestId='%s', message='%s', certificateSize=%d}", 
            success, requestId, message, certificateData != null ? certificateData.length : 0);
    }
}