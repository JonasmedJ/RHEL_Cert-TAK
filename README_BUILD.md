# How to Build the RHEL IDM Certificate Plugin

This guide explains how to build the plugin JAR file using GitHub Actions (automatic) or manually.

## Option 1: GitHub Actions (RECOMMENDED - Automatic Build with Internet)

GitHub Actions will automatically build your plugin whenever you push code. **This is the easiest method since you don't need internet access on your local machine.**

### How It Works

1. **Automatic Builds**: When you push to the `main` branch or any `claude/*` branch, GitHub Actions will:
   - Download all dependencies from Maven Central
   - Compile your plugin
   - Create a fat JAR with all dependencies bundled
   - Make it available for download

2. **Download the Built JAR**:

   a. Go to your GitHub repository: https://github.com/JonasmedJ/RHEL_Cert-TAK

   b. Click on the "Actions" tab at the top

   c. Click on the latest successful build (green checkmark)

   d. Scroll down to "Artifacts" section

   e. Download "rhel-idm-certificate-plugin"

   f. Extract the ZIP file - your JAR will be inside: `rhel-idm-certificate-plugin-1.0.0.jar`

3. **Manual Trigger** (if needed):

   - Go to Actions tab
   - Click on "Build TAK Server Plugin" workflow
   - Click "Run workflow" button
   - Select the branch and click "Run workflow"

### Deploy to TAK Server

```bash
# Copy the downloaded JAR to TAK Server
sudo cp rhel-idm-certificate-plugin-1.0.0.jar /opt/tak/plugins/

# Restart TAK Server to load the plugin
sudo systemctl restart takserver

# Verify plugin loaded
sudo tail -f /opt/tak/logs/takserver.log | grep -i "rhel"
```

## Option 2: Build Manually on a Machine with Internet

If you have access to another machine with internet:

```bash
# Clone the repository
git clone https://github.com/JonasmedJ/RHEL_Cert-TAK.git
cd RHEL_Cert-TAK

# Checkout the correct branch
git checkout claude/debug-and-fix-011CUoR2aDioyr93quHSMmJ5

# Build the plugin (downloads dependencies automatically)
./gradlew clean shadowJar

# The JAR will be at:
# app/build/libs/rhel-idm-certificate-plugin-1.0.0.jar

# Transfer this JAR to your TAK Server machine
```

## Option 3: Build Offline (Advanced)

If you must build offline, you need to:

1. **On a machine WITH internet**, download all dependencies:
   ```bash
   ./gradlew clean build --refresh-dependencies

   # Package your local Maven cache
   tar czf maven-deps.tar.gz ~/.gradle/caches/ ~/.m2/repository/
   ```

2. **Transfer to offline machine**:
   ```bash
   # Extract dependencies
   tar xzf maven-deps.tar.gz -C ~/
   ```

3. **Build offline**:
   ```bash
   ./gradlew clean shadowJar --offline
   ```

## What Gets Built

The build creates a "fat JAR" (also called "uber JAR") that includes:

✅ Your plugin code
✅ All dependencies (Spring, BouncyCastle, LDAP libraries, etc.)
✅ Plugin stub interfaces (Message, MessageInterceptorBase, TakServerPlugin)
✅ Proper manifest with Plugin-Class attribute

**Important Notes:**

1. **TAK Server Plugin Interfaces**: The JAR includes stub interfaces that match TAK Server's plugin API. When loaded by TAK Server, the server's actual classes will be used instead of our stubs (via Java's classloader parent-first delegation).

2. **Dependency Relocation**: Some dependencies (Spring, Jackson) are "relocated" to avoid conflicts with TAK Server's own dependencies.

3. **No artifacts.tak.gov Required**: This build does NOT require access to artifacts.tak.gov since we use our own stub interfaces.

## Verifying the Build

After building, verify the JAR:

```bash
# Check JAR contents
jar tf app/build/libs/rhel-idm-certificate-plugin-1.0.0.jar | grep "tak/server/plugins"

# Should show:
# tak/server/plugins/rhelidmcert/RhelIdmCertificatePlugin.class
# tak/server/plugins/Message.class
# tak/server/plugins/MessageInterceptorBase.class
# etc.

# Check manifest
unzip -p app/build/libs/rhel-idm-certificate-plugin-1.0.0.jar META-INF/MANIFEST.MF

# Should contain:
# Plugin-Class: tak.server.plugins.rhelidmcert.RhelIdmCertificatePlugin
```

## Troubleshooting

### "Could not resolve dependencies" error
- You need internet access or pre-downloaded dependencies
- Use GitHub Actions (Option 1) or build on a machine with internet (Option 2)

### GitHub Actions build fails
- Check the Actions tab for error logs
- Ensure the workflow file is in `.github/workflows/build-plugin.yml`
- Make sure you pushed the latest changes

### Plugin doesn't load in TAK Server
- Check TAK Server logs: `/opt/tak/logs/takserver.log`
- Verify plugin is in correct location: `/opt/tak/plugins/`
- Ensure TAK Server was restarted: `sudo systemctl restart takserver`
- Check plugin package is `tak.server.plugins.*` (required by TAK Server)

## Configuration

After deploying, create the configuration file:

`/opt/tak/conf/plugins/rhel-idm-cert-plugin.yml`

```yaml
ldap:
  serverUrl: "ldaps://idm.example.com:636"
  bindDn: "uid=takserver,cn=users,cn=accounts,dc=example,dc=com"
  bindPassword: "your-service-account-password"
  baseDn: "cn=users,cn=accounts,dc=example,dc=com"
  useSsl: true

certificate:
  keySize: 2048
  defaultOrganization: "Your Organization"
```

## Next Steps

1. Push your code to GitHub (it's already committed)
2. Go to GitHub Actions tab
3. Download the built JAR
4. Deploy to TAK Server
5. Configure the plugin
6. Test certificate enrollment
