/**
 * SHA1HULUD Malware Scanner
 * Detects malicious npm packages from the SHA1HULUD supply chain attack
 */

const fs = require('fs');
const path = require('path');

// Simple semver comparison helpers
function parseVersion(versionString) {
  const match = versionString.match(/(\d+)\.(\d+)\.(\d+)/);
  if (!match) return null;
  return {
    major: parseInt(match[1], 10),
    minor: parseInt(match[2], 10),
    patch: parseInt(match[3], 10)
  };
}

function versionMatches(rangeSpec, targetVersion) {
  rangeSpec = rangeSpec.trim();
  targetVersion = targetVersion.trim();

  if (rangeSpec === targetVersion) return true;

  const range = parseVersion(rangeSpec.replace(/^[\^~]/, ''));
  const target = parseVersion(targetVersion);

  if (!range || !target) return false;

  // Caret (^) - allows changes that do not modify the left-most non-zero digit
  if (rangeSpec.startsWith('^')) {
    if (range.major === 0) {
      if (range.minor === 0) {
        return target.major === 0 && target.minor === 0 && target.patch === range.patch;
      }
      return target.major === 0 && target.minor === range.minor && target.patch >= range.patch;
    }
    return target.major === range.major &&
           (target.minor > range.minor ||
            (target.minor === range.minor && target.patch >= range.patch));
  }

  // Tilde (~) - allows patch-level changes
  if (rangeSpec.startsWith('~')) {
    return target.major === range.major &&
           target.minor === range.minor &&
           target.patch >= range.patch;
  }

  // No prefix - exact match
  return target.major === range.major &&
         target.minor === range.minor &&
         target.patch === range.patch;
}

class MalwareScanner {
  constructor(config = {}) {
    this.config = {
      scanPath: config.scanPath || process.cwd(),
      dataPath: config.dataPath || path.join(__dirname, '../data/malicious-packages-detailed.js'),
      excludeDirs: config.excludeDirs || ['node_modules', '.git', '.cache', 'dist', 'build'],
      verbose: config.verbose !== undefined ? config.verbose : false,
      outputFormat: config.outputFormat || 'console', // 'console' | 'json'
      streamOutput: config.streamOutput !== undefined ? config.streamOutput : true, // Show results as we scan
      ...config
    };

    this.findings = [];
    this.scannedFiles = 0;
    this.scannedDirs = 0;
    this.currentProjectFindings = [];
    this.currentProjectPath = null;

    this.dependencyFiles = [
      'package.json',
      'package-lock.json',
      'yarn.lock',
      'pnpm-lock.yaml',
      'npm-shrinkwrap.json'
    ];

    // Load malicious packages database
    try {
      const MALICIOUS_DATA = require(this.config.dataPath);
      this.maliciousPackages = MALICIOUS_DATA.packageNames;
      this.maliciousVersions = MALICIOUS_DATA.packageVersions;
    } catch (error) {
      throw new Error(`Failed to load malicious packages database: ${error.message}`);
    }
  }

  scan() {
    if (!fs.existsSync(this.config.scanPath)) {
      throw new Error(`Scan path not found: ${this.config.scanPath}`);
    }

    if (this.config.streamOutput) {
      console.log(`🔍 Starting scan: ${this.config.scanPath}`);
    } else if (this.config.verbose) {
      console.log(`🔍 Scanning: ${this.config.scanPath}\n`);
    }

    this.walkDirectory(this.config.scanPath);

    // Print results for the last project
    if (this.currentProjectPath && this.config.streamOutput) {
      this.printProjectResults();
    }

    return {
      summary: {
        directoriesScanned: this.scannedDirs,
        filesScanned: this.scannedFiles,
        maliciousPackagesInDb: this.maliciousPackages.length,
        maliciousVersionsInDb: Object.values(this.maliciousVersions).flat().length,
        findingsCount: this.findings.length,
        criticalCount: this.findings.filter(f => f.severity === 'CRITICAL').length,
        warningCount: this.findings.filter(f => f.severity === 'WARNING').length,
        infoCount: this.findings.filter(f => f.severity === 'INFO').length
      },
      findings: this.findings
    };
  }

  walkDirectory(dir) {
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch (error) {
      if (this.config.verbose) {
        console.warn(`⚠️  Cannot read directory ${dir}: ${error.message}`);
      }
      return;
    }

    this.scannedDirs++;

    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);

      if (entry.isDirectory()) {
        if (this.config.excludeDirs.includes(entry.name)) {
          continue;
        }
        this.walkDirectory(fullPath);
      } else if (entry.isFile() && this.dependencyFiles.includes(entry.name)) {
        this.scanFile(fullPath);
      }
    }
  }

  scanFile(filePath) {
    this.scannedFiles++;

    // Check if this is a new project (package.json in a new directory)
    const projectDir = path.dirname(filePath);
    const isPackageJson = filePath.endsWith('package.json');

    if (isPackageJson && projectDir !== this.currentProjectPath) {
      // Print results from previous project if any
      if (this.currentProjectPath && this.config.streamOutput) {
        this.printProjectResults();
      }

      // Start tracking new project
      this.currentProjectPath = projectDir;
      this.currentProjectFindings = [];

      if (this.config.streamOutput) {
        console.log(`\n📦 Scanning project: ${projectDir}`);
      }
    }

    try {
      const content = fs.readFileSync(filePath, 'utf8');
      const findingsBeforeCount = this.findings.length;

      if (filePath.endsWith('.json')) {
        this.scanJsonFile(filePath, content);
      } else if (filePath.endsWith('.lock') || filePath.endsWith('.yaml')) {
        this.scanLockFile(filePath, content);
      }

      // Track findings for current project
      const newFindings = this.findings.slice(findingsBeforeCount);
      this.currentProjectFindings.push(...newFindings);
    } catch (error) {
      if (this.config.verbose) {
        console.warn(`⚠️  Cannot read file ${filePath}: ${error.message}`);
      }
    }
  }

  printProjectResults() {
    if (this.currentProjectFindings.length === 0) {
      console.log(`   ✅ Clean - No issues found`);
      return;
    }

    const criticalCount = this.currentProjectFindings.filter(f => f.severity === 'CRITICAL').length;
    const warningCount = this.currentProjectFindings.filter(f => f.severity === 'WARNING').length;

    if (criticalCount > 0) {
      console.log(`   🔴 CRITICAL: ${criticalCount} issue(s) found`);
      this.currentProjectFindings
        .filter(f => f.severity === 'CRITICAL')
        .forEach(f => {
          console.log(`      ❌ ${f.package}@${f.version}`);
          console.log(`         ${f.message}`);
        });
    }

    if (warningCount > 0) {
      console.log(`   🟡 WARNING: ${warningCount} issue(s) found`);
      if (this.config.verbose) {
        this.currentProjectFindings
          .filter(f => f.severity === 'WARNING')
          .forEach(f => {
            console.log(`      ⚠️  ${f.package}@${f.version}`);
            console.log(`         ${f.message}`);
          });
      }
    }
  }

  checkVersionAgainstMalicious(pkgName, versionSpec) {
    if (!this.maliciousVersions[pkgName]) {
      return { matches: false, matchedVersions: [], allMaliciousVersions: [] };
    }

    const matchedVersions = [];
    const maliciousVersions = this.maliciousVersions[pkgName];

    for (const maliciousVersion of maliciousVersions) {
      if (versionMatches(versionSpec, maliciousVersion)) {
        matchedVersions.push(maliciousVersion);
      }
    }

    return {
      matches: matchedVersions.length > 0,
      matchedVersions: matchedVersions,
      allMaliciousVersions: maliciousVersions
    };
  }

  scanJsonFile(filePath, content) {
    try {
      const json = JSON.parse(content);
      const allDeps = {
        ...json.dependencies,
        ...json.devDependencies,
        ...json.optionalDependencies,
        ...json.peerDependencies
      };

      for (const pkgName of Object.keys(allDeps || {})) {
        if (this.maliciousPackages.includes(pkgName)) {
          const versionSpec = allDeps[pkgName];
          const versionCheck = this.checkVersionAgainstMalicious(pkgName, versionSpec);

          let severity = 'INFO';
          let message = 'Package name matches malicious list';

          if (versionCheck.matches) {
            severity = 'CRITICAL';
            message = `Version range '${versionSpec}' could install malicious version(s): ${versionCheck.matchedVersions.join(', ')}`;
          } else if (versionCheck.allMaliciousVersions.length > 0) {
            severity = 'WARNING';
            message = `Version '${versionSpec}' appears safe. Known malicious: ${versionCheck.allMaliciousVersions.join(', ')}`;
          }

          this.findings.push({
            file: filePath,
            package: pkgName,
            version: versionSpec,
            type: 'package.json',
            severity: severity,
            message: message,
            matchedMaliciousVersions: versionCheck.matchedVersions,
            allKnownMaliciousVersions: versionCheck.allMaliciousVersions
          });
        }
      }
    } catch (error) {
      // Invalid JSON, skip
    }
  }

  scanLockFile(filePath, content) {
    for (const maliciousPkg of this.maliciousPackages) {
      const regex = new RegExp(`["']${maliciousPkg.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}["']`, 'g');
      if (regex.test(content)) {
        const versionMatch = content.match(
          new RegExp(`["']${maliciousPkg.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}["'][\\s\\S]{0,200}version["\']?:\\s*["']([^"']+)["']`)
        );
        const version = versionMatch ? versionMatch[1] : 'unknown';

        if (version !== 'unknown') {
          const versionCheck = this.checkVersionAgainstMalicious(maliciousPkg, version);

          let severity = 'WARNING';
          let message = `Package found in lock file with version ${version}`;

          if (versionCheck.matches) {
            severity = 'CRITICAL';
            message = `CONFIRMED MALICIOUS version installed: ${version}`;
          } else if (versionCheck.allMaliciousVersions.length > 0) {
            message = `Installed version ${version} appears safe. Known malicious: ${versionCheck.allMaliciousVersions.join(', ')}`;
          }

          this.findings.push({
            file: filePath,
            package: maliciousPkg,
            version: version,
            type: 'lock file',
            severity: severity,
            message: message,
            matchedMaliciousVersions: versionCheck.matchedVersions,
            allKnownMaliciousVersions: versionCheck.allMaliciousVersions
          });
        }
      }
    }
  }
}

module.exports = MalwareScanner;
