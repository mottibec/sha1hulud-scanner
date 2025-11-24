# SHA1HULUD Scanner

🔍 **Detect malicious npm packages from the SHA1HULUD supply chain attack**

This scanner helps identify if your projects are affected by the SHA1HULUD malware campaign, which compromised over 800 npm packages including popular libraries like PostHog, Voiceflow, AsyncAPI, ENS Domains, Zapier, and many others.

## ⚠️ What is SHA1HULUD?

SHA1HULUD is a massive supply chain attack discovered on November 24, 2025, targeting the npm ecosystem. Attackers published malicious versions of hundreds of legitimate packages that could:

- Steal environment variables and credentials
- Exfiltrate sensitive data
- Execute arbitrary code
- Compromise your entire system

**Source:** [HelixGuard Security Alert](https://helixguard.ai/blog/malicious-sha1hulud-2025-11-24)

## 🚀 Quick Start

### Global Installation

```bash
npm install -g sha1hulud-scanner
sha1hulud-scanner
```

### Local Usage (No Installation)

```bash
npx sha1hulud-scanner
```

### From Source

```bash
git clone https://github.com/mottibec/sha1hulud-scanner.git
cd sha1hulud-scanner
node bin/sha1hulud-scanner.js
```

## 📋 Features

- ✅ **Detects 622 compromised packages** with 860 malicious versions
- ✅ **Smart semver range checking** - detects if `^` or `~` ranges could install malicious versions
- ✅ **Fast recursive scanning** - scans entire project trees
- ✅ **Multiple output formats** - console (human-readable) or JSON (machine-readable)
- ✅ **Configurable** - customize scan paths, exclusions, and verbosity
- ✅ **Exit codes** - integrates with CI/CD pipelines
- ✅ **Zero dependencies** - pure Node.js implementation

## 🎯 Usage

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

## 🔍 What It Scans

The scanner checks the following files:

- `package.json` - Direct dependencies
- `package-lock.json` - Locked versions
- `yarn.lock` - Yarn lock file
- `pnpm-lock.yaml` - pnpm lock file
- `npm-shrinkwrap.json` - npm shrinkwrap file

## 📊 Understanding Results

### Severity Levels

- **🔴 CRITICAL**: Your version range could install a malicious version, or you have a malicious version installed
- **🟡 WARNING**: Package name matches but your version appears safe (verify in lock files)
- **ℹ️  INFO**: Package found but no specific threat detected

### Exit Codes

- `0` - Clean, no issues found
- `1` - Warnings found (verification needed)
- `2` - Critical issues found (immediate action required)
- `3` - Error during scan

## 🛡️ What To Do If Infected

### If CRITICAL Issues Found:

1. **DO NOT run `npm install` or `npm update`** - this could install malicious versions
2. **Check your lock files** to see what's actually installed
3. **If malicious versions are installed:**
   - Disconnect from network immediately
   - Remove malicious packages
   - Rotate ALL credentials (API keys, passwords, tokens, secrets)
   - Check for unauthorized access and data exfiltration
   - Review system logs for suspicious activity
4. **Pin safe versions** - Remove `^` and `~` from package.json
5. **Update to latest safe versions** from official package maintainers

### If Warnings Found:

1. Check lock files to verify installed versions
2. Do NOT run npm install without verifying versions first
3. Pin versions to prevent accidental upgrades
4. Monitor package maintainer announcements

## 🔧 Programmatic Usage

You can use the scanner in your own Node.js scripts:

```javascript
const MalwareScanner = require('sha1hulud-scanner');

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
    console.log(`⚠️  ${finding.package}@${finding.version} in ${finding.file}`);
  }
});
```

## 🤝 Contributing

We welcome contributions! Here's how you can help:

1. **Report false positives/negatives** - Open an issue
2. **Add new malicious packages** - Submit a PR with updated data
3. **Improve detection logic** - Submit a PR with enhancements
4. **Documentation** - Help improve this README

## 📝 Database Updates

The malicious package database is located in `data/malicious-packages-detailed.js`. To update:

1. Get the latest data from [HelixGuard](https://helixguard.ai/blog/malicious-sha1hulud-2025-11-24)
2. Run the data extraction script (if provided)
3. Update the database file
4. Test with `npm run test`
5. Submit a PR

## ⚖️ License

MIT License - see [LICENSE](LICENSE) file for details

## 🙏 Credits

- **HelixGuard** for discovering and documenting the SHA1HULUD attack
- **npm Security Team** for their ongoing work to secure the ecosystem
- **Open Source Community** for contributing to this tool

## 📚 Additional Resources

- [HelixGuard SHA1HULUD Report](https://helixguard.ai/blog/malicious-sha1hulud-2025-11-24)
- [npm Security Best Practices](https://docs.npmjs.com/security-best-practices)
- [Supply Chain Security Guide](https://github.com/ossf/wg-securing-software-repos)

## ⚠️ Disclaimer

This tool is provided as-is for security scanning purposes. While we strive for accuracy, it may not detect all threats or may produce false positives. Always verify findings and follow security best practices.

## 🐛 Reporting Issues

Found a bug or have a feature request? Please open an issue on our [GitHub Issues page](https://github.com/mottibec/sha1hulud-scanner/issues).

---

**Stay Safe! 🛡️**

If you find this tool helpful, please ⭐ star the repository and share it with others!
