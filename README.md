# Sha1-Hulud Scanner

**Detect malicious npm packages from Sha1-Hulud: The Second Coming supply chain attack**

This scanner helps identify if your projects are affected by the Sha1-Hulud malware campaign, which has compromised over 800 npm packages including popular libraries like PostHog, Voiceflow, AsyncAPI, ENS Domains, Zapier, and many others. This is a resurgence of the original Shai-Hulud attack with significantly more destructive capabilities.

## CRITICAL: What is Sha1-Hulud: The Second Coming?

Sha1-Hulud: The Second Coming is a massive supply chain attack discovered on November 24, 2025, targeting the npm ecosystem. This new variant has affected tens of thousands of GitHub repositories across multiple maintainers and ecosystems.

Attackers published malicious versions of hundreds of legitimate packages that:

- Steal environment variables and credentials
- Capture developer tokens and API keys
- Exfiltrate sensitive data
- Establish persistent footholds in repositories
- **DESTRUCTIVE FALLBACK**: If the malware fails to authenticate or establish persistence, it attempts to **delete your entire home directory**, removing every writable file owned by the current user

**Source:** [HelixGuard Security Alert](https://helixguard.ai/blog/malicious-sha1hulud-2025-11-24)

## Quick Start

### 1. Install from GitHub Packages

```bash
npm install -g @mottibec/sha1hulud-scanner
sha1hulud-scanner
```

### 2. Local/One-Off Usage

```bash
npx @mottibec/sha1hulud-scanner
```

### 3. From Source

```bash
git clone https://github.com/mottibec/sha1hulud-scanner.git
cd sha1hulud-scanner
node bin/sha1hulud-scanner.js
```

## Features

- **Detects 622 compromised packages** with 860 malicious versions
- **Smart semver range checking** - detects if `^` or `~` ranges could install malicious versions
- **Fast recursive scanning** - scans entire project trees
- **Multiple output formats** - console (human-readable) or JSON (machine-readable)
- **Configurable** - customize scan paths, exclusions, and verbosity
- **Exit codes** - integrates with CI/CD pipelines
- **Zero dependencies** - pure Node.js implementation

## Usage

### Basic Scan

Scan the current directory:

```bash
sha1hulud-scanner
```

Scan a specific directory:

```bash
sha1hulud-scanner /path/to/your/project
```

### Advanced Options

```bash
sha1hulud-scanner [options] [path]

Options:
  -h, --help           Show help message
  -v, --version        Show version number
  --verbose            Show detailed scanning progress
  --json               Output results in JSON format
  --exclude <dirs>     Comma-separated directories to exclude
                       (default: node_modules,.git,.cache,dist,build)
```

### Examples

Verbose scan with detailed output:

```bash
sha1hulud-scanner --verbose
```

Export results as JSON:

```bash
sha1hulud-scanner --json > scan-results.json
```

Scan with custom exclusions:

```bash
sha1hulud-scanner --exclude "node_modules,dist,custom-dir"
```

Scan multiple projects:

```bash
for dir in project1 project2 project3; do
  sha1hulud-scanner "$dir"
done
```

## What It Scans

The scanner checks the following files:

- `package.json` - Direct dependencies
- `package-lock.json` - Locked versions
- `yarn.lock` - Yarn lock file
- `pnpm-lock.yaml` - pnpm lock file
- `npm-shrinkwrap.json` - npm shrinkwrap file

## Understanding Results

### Severity Levels

- **CRITICAL**: Your version range could install a malicious version, or you have a malicious version installed
- **WARNING**: Package name matches but your version appears safe (verify in lock files)
- **INFO**: Package found but no specific threat detected

### Exit Codes

- `0` - Clean, no issues found
- `1` - Warnings found (verification needed)
- `2` - Critical issues found (immediate action required)
- `3` - Error during scan

## What To Do If Infected

### If CRITICAL Issues Found:

**IMMEDIATE ACTIONS - Time Critical:**

1. **STOP - DO NOT run `npm install` or `npm update`** - This will trigger the malicious payload
2. **Isolate the system** - Disconnect from network IMMEDIATELY to prevent data exfiltration
3. **Check your lock files** to see what's actually installed
4. **If malicious versions are confirmed installed:**
   - **URGENT**: The malware may attempt to delete your entire home directory if it cannot establish persistence
   - Back up critical data immediately if not already backed up
   - Disconnect all network access
   - Remove malicious packages carefully
   - Rotate ALL credentials (API keys, passwords, tokens, secrets, SSH keys, GPG keys)
   - Check for unauthorized access and data exfiltration
   - Review system logs for suspicious activity
   - Scan for persistent backdoors in your repositories
   - Check GitHub/GitLab access logs for unauthorized pushes
5. **Pin safe versions** - Remove `^` and `~` from package.json
6. **Update to latest safe versions** from official package maintainers

### If Warnings Found:

1. Check lock files to verify installed versions
2. Do NOT run npm install without verifying versions first
3. Pin versions to prevent accidental upgrades
4. Monitor package maintainer announcements

## Programmatic Usage

You can use the scanner in your own Node.js scripts:

```javascript
const MalwareScanner = require('@mottibec/sha1hulud-scanner');

const scanner = new MalwareScanner({
  scanPath: '/path/to/project',
  verbose: true,
  excludeDirs: ['node_modules', '.git']
});

const results = scanner.scan();

console.log(`Found ${results.summary.criticalCount} critical issues`);
console.log(`Scanned ${results.summary.filesScanned} files`);

// Process findings
results.findings.forEach(finding => {
  if (finding.severity === 'CRITICAL') {
    console.log(`${finding.package}@${finding.version} in ${finding.file}`);
  }
});
```

## Contributing

We welcome contributions! Here's how you can help:

1. **Report false positives/negatives** - Open an issue
2. **Add new malicious packages** - Submit a PR with updated data
3. **Improve detection logic** - Submit a PR with enhancements
4. **Documentation** - Help improve this README

## Database Updates

The malicious package database is located in `data/malicious-packages-detailed.js`. To update:

1. Get the latest data from [HelixGuard](https://helixguard.ai/blog/malicious-sha1hulud-2025-11-24)
2. Run the data extraction script (if provided)
3. Update the database file
4. Test with `npm run test`
5. Submit a PR

## License

MIT License - see [LICENSE](LICENSE) file for details

## Disclaimer

This tool is provided as-is for security scanning purposes. While we strive for accuracy, it may not detect all threats or may produce false positives. Always verify findings and follow security best practices.

## Reporting Issues

Found a bug or have a feature request? Please open an issue on our [GitHub Issues page](https://github.com/mottibec/sha1hulud-scanner/issues).

---

**Stay Safe!**

If you find this tool helpful, please star the repository and share it with others!
