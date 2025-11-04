package tak.server.plugins;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Base class for TAK Server message interceptor plugins.
 *
 * Plugins that extend this class can intercept and process messages
 * flowing through the TAK Server.
 */
public abstract class MessageInterceptorBase {

    protected final Logger logger = LoggerFactory.getLogger(getClass());

    /**
     * Called when the plugin is started by TAK Server.
     * Override this method to initialize resources, connections, etc.
     */
    public void start() {
        logger.info("Starting plugin: {}", getClass().getName());
    }

    /**
     * Called when the plugin is stopped by TAK Server.
     * Override this method to clean up resources, close connections, etc.
     */
    public void stop() {
        logger.info("Stopping plugin: {}", getClass().getName());
    }

    /**
     * Intercept and optionally modify messages passing through TAK Server.
     *
     * @param message The message to intercept
     * @return The message (possibly modified) to continue processing, or null to drop the message
     */
    public abstract Message intercept(Message message);
}