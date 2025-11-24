#!/usr/bin/env node

const path = require('path');
const MalwareScanner = require('../src/scanner');
const pkg = require('../package.json');

function printHelp() {
  console.log(`sha1hulud-scanner v${pkg.version}

Usage: sha1hulud-scanner [options] [path]

Options:
  -h, --help           Show this help message
  -v, --version        Show version number
  --verbose            Show detailed scanning progress
  --json               Output results in JSON format
  --exclude <dirs>     Comma-separated directories to exclude
                       (default: node_modules,.git,.cache,dist,build)
`);
}

function parseArgs(argv) {
  const args = [...argv];
  const config = {};
  let scanPath = process.cwd();

  while (args.length > 0) {
    const arg = args.shift();

    if (arg === '-h' || arg === '--help') {
      printHelp();
      process.exit(0);
    }

    if (arg === '-v' || arg === '--version') {
      console.log(pkg.version);
      process.exit(0);
    }

    if (arg === '--verbose') {
      config.verbose = true;
      continue;
    }

    if (arg === '--json') {
      config.outputFormat = 'json';
      config.streamOutput = false;
      continue;
    }

    if (arg === '--exclude') {
      const dirs = args.shift();
      if (!dirs) {
        console.error('Error: --exclude requires a comma-separated list of directories.');
        process.exit(1);
      }
      config.excludeDirs = dirs.split(',').map(d => d.trim()).filter(Boolean);
      continue;
    }

    if (arg.startsWith('-')) {
      console.error(`Unknown option: ${arg}`);
      process.exit(1);
    }

    // Positional path argument
    scanPath = path.resolve(arg);
  }

  config.scanPath = scanPath;
  return config;
}

function main() {
  try {
    const config = parseArgs(process.argv.slice(2));
    const scanner = new MalwareScanner(config);
    const results = scanner.scan();

    if (config.outputFormat === 'json') {
      console.log(JSON.stringify(results, null, 2));
    }
  } catch (error) {
    console.error(`sha1hulud-scanner error: ${error.message}`);
    process.exit(3);
  }
}

main();

