package tak.server.plugins;


public abstract class MessageInterceptorBase {
    
    // Plugin lifecycle methods
    public abstract void onPluginLoaded(PluginManager pluginManager);
    public abstract void onPluginUnloaded();
    
    // Message interception
    public abstract Object intercept(Object message);
    
    // Plugin info
    public abstract PluginInfo getPluginInfo();
}