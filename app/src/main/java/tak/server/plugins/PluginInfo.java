package tak.server.plugins;

public class PluginInfo {
    private String name;
    private String version; 
    private String description;
    
    private PluginInfo(Builder builder) {
        this.name = builder.name;
        this.version = builder.version;
        this.description = builder.description;
    }
    
    public static Builder builder() {
        return new Builder();
    }
    
    public String getName() { return name; }
    public String getVersion() { return version; }
    public String getDescription() { return description; }
    
    public static class Builder {
        private String name;
        private String version;
        private String description;
        
        public Builder name(String name) { this.name = name; return this; }
        public Builder version(String version) { this.version = version; return this; }
        public Builder description(String description) { this.description = description; return this; }
        public PluginInfo build() { return new PluginInfo(this); }
    }
}
