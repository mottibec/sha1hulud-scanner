#!/usr/bin/env node

/**
 * Sha1-Hulud Scanner CLI
 * Detects malicious npm packages from Sha1-Hulud: The Second Coming supply chain attack
 *
 * Source: https://helixguard.ai/blog/malicious-sha1hulud-2025-11-24
 */

const path = require('path');
const MalwareScanner = require('../src/scanner');
const Reporter = require('../src/reporter');

const VERSION = '1.1.0';

function printUsage() {
  console.log(`
Sha1-Hulud Scanner v${VERSION}

Scans your npm projects for malicious packages from Sha1-Hulud: The Second Coming supply chain attack.
WARNING: This malware can delete your entire home directory if persistence fails.

Usage:
  sha1hulud-scanner [options] [path]

Arguments:
  path                  Directory to scan (default: current directory)

Options:
  -h, --help           Show this help message
  -v, --version        Show version number
  --verbose            Show detailed scanning progress
  --json               Output results in JSON format
  --exclude <dirs>     Comma-separated list of directories to exclude
                       (default: node_modules,.git,.cache,dist,build)

Examples:
  sha1hulud-scanner                    # Scan current directory
  sha1hulud-scanner /path/to/project   # Scan specific directory
  sha1hulud-scanner --verbose          # Scan with detailed output
  sha1hulud-scanner --json > results.json  # Save results as JSON
  sha1hulud-scanner --exclude "node_modules,dist,custom-dir"

Exit codes:
  0  No issues found
  1  Warnings found (potential issues)
  2  Critical issues found (action required)
  3  Error during scan
`);
}

function parseArgs(args) {
  const config = {
    scanPath: process.cwd(),
    verbose: false,
    outputFormat: 'console',
    excludeDirs: ['node_modules', '.git', '.cache', 'dist', 'build']
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];

    switch (arg) {
      case '-h':
      case '--help':
        printUsage();
        process.exit(0);
        break;

      case '-v':
      case '--version':
        console.log(`v${VERSION}`);
        process.exit(0);
        break;

      case '--verbose':
        config.verbose = true;
        break;

      case '--json':
        config.outputFormat = 'json';
        break;

      case '--exclude':
        if (i + 1 < args.length) {
          config.excludeDirs = args[++i].split(',').map(d => d.trim());
        } else {
          console.error('Error: --exclude requires a value');
          process.exit(3);
        }
        break;

      default:
        if (!arg.startsWith('-')) {
          config.scanPath = path.resolve(arg);
        } else {
          console.error(`Error: Unknown option '${arg}'`);
          printUsage();
          process.exit(3);
        }
    }
  }

  return config;
}

function main() {
  const args = process.argv.slice(2);
  const config = parseArgs(args);

  try {
    // Set data path relative to this script
    config.dataPath = path.join(__dirname, '../data/malicious-packages-detailed.js');

    // Disable stream output for JSON format (to avoid mixing logs with JSON)
    if (config.outputFormat === 'json') {
      config.streamOutput = false;
    }

    const scanner = new MalwareScanner(config);
    const results = scanner.scan();

    if (config.outputFormat === 'json') {
      console.log(Reporter.formatJson(results));
    } else {
      Reporter.formatConsole(results);
    }

    // Determine exit code
    const { criticalCount, warningCount } = results.summary;

    if (criticalCount > 0) {
      process.exit(2);
    } else if (warningCount > 0) {
      process.exit(1);
    } else {
      process.exit(0);
    }
  } catch (error) {
    console.error(`\n❌ Error: ${error.message}\n`);
    if (config.verbose) {
      console.error(error.stack);
    }
    process.exit(3);
  }
}

if (require.main === module) {
  main();
}

module.exports = { parseArgs, VERSION };
