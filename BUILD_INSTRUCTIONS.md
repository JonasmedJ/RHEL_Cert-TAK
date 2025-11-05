# Building the RHEL IDM Certificate Plugin for TAK Server

## Prerequisites

### 1. TAK Server Plugin SDK
You need the TAK Server plugin SDK JAR file to compile this plugin. This can be obtained from:

**Option A: From TAK Server Installation**
```bash
# If you have TAK Server installed
ls /opt/tak/lib/takserver-plugin-*.jar
```

**Option B: From TAK Server SDK Repository**
```bash
# Clone the SDK repository
git clone https://github.com/JonasmedJ/Takserver-SDK
cd Takserver-SDK/tak-server-sdk-5.5/tak-server-sdk

# The plugin SDK JAR should be in the lib/ directory
ls lib/*.jar
```

### 2. Set Up Local Lib Directory
Once you have the TAK Server plugin JAR:

```bash
# Create a local lib directory in the project
mkdir -p app/libs

# Copy the TAK Server plugin JAR
cp /path/to/takserver-plugin-*.jar app/libs/
```

## Building the Plugin

### Option 1: Build with Internet Access (Downloads Dependencies)
If you have internet connectivity to download Maven dependencies:

```bash
# Clean and build
./gradlew clean build

# The plugin JAR will be in: app/build/libs/rhel-idm-certificate-plugin-1.0.0.jar
```

### Option 2: Build with Pre-Downloaded Dependencies
If you need to build offline:

1. **On a machine WITH internet access**, download dependencies:
```bash
# Download all dependencies to local Maven cache
./gradlew clean build --refresh-dependencies

# Dependencies will be in ~/.m2/repository/
# Package the entire ~/.m2/repository/ directory
tar czf maven-dependencies.tar.gz ~/.m2/repository/
```

2. **Transfer to offline machine:**
```bash
# Extract dependencies on the offline machine
tar xzf maven-dependencies.tar.gz -C ~/
```

3. **Build offline:**
```bash
./gradlew clean build --offline
```

## Deploying to TAK Server

Once built, deploy the plugin:

```bash
# Copy plugin JAR to TAK Server
sudo cp app/build/libs/rhel-idm-certificate-plugin-1.0.0.jar /opt/tak/plugins/

# Restart TAK Server
sudo systemctl restart takserver

# Check plugin loaded successfully
sudo tail -f /opt/tak/logs/takserver.log | grep -i "rhel"
```

## Configuration

Create plugin configuration at `/opt/tak/conf/plugins/rhel-idm-cert-plugin.yml`:

```yaml
ldap:
  serverUrl: "ldaps://idm.example.com:636"
  bindDn: "uid=takserver,cn=users,cn=accounts,dc=example,dc=com"
  bindPassword: "your-service-account-password"
  baseDn: "cn=users,cn=accounts,dc=example,dc=com"
  useSsl: true

certificate:
  keySize: 2048
  defaultOrganization: "Example Organization"
```

## Troubleshooting

### Build Fails: "Could not resolve dependencies"
- You need internet access or pre-downloaded dependencies
- See "Option 2: Build with Pre-Downloaded Dependencies" above

### Build Fails: "Cannot find TAK Server plugin classes"
- You need the TAK Server plugin SDK JAR in `app/libs/`
- See "Prerequisites" section above

### Plugin Not Loading in TAK Server
- Check plugin is in correct package: `tak.server.plugins.*`
- Check TAK Server logs: `/opt/tak/logs/takserver.log`
- Verify JAR has correct manifest and @TakServerPlugin annotation
