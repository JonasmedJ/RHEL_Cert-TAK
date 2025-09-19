package tak.server.plugins;

public interface PluginManager {
    // Minimal interface for plugin manager
    void registerPlugin(Object plugin);
    void sendMessage(Object message);
}