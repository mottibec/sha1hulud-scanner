/**
 * Report formatter for scan results
 */

class Reporter {
  static formatConsole(results) {
    const { summary, findings } = results;

    console.log('\n' + '='.repeat(70));
    console.log('📊 SHA1HULUD MALWARE SCAN RESULTS');
    console.log('='.repeat(70));
    console.log(`Directories scanned: ${summary.directoriesScanned}`);
    console.log(`Files scanned: ${summary.filesScanned}`);
    console.log(`Malicious packages in database: ${summary.maliciousPackagesInDb}`);
    console.log(`Known malicious versions: ${summary.maliciousVersionsInDb}`);
    console.log('='.repeat(70) + '\n');

    if (findings.length === 0) {
      console.log('✅ CLEAN: No malicious packages detected!\n');
      return;
    }

    const critical = findings.filter(f => f.severity === 'CRITICAL');
    const warnings = findings.filter(f => f.severity === 'WARNING');
    const info = findings.filter(f => f.severity === 'INFO');

    if (critical.length > 0) {
      console.log('🚨 CRITICAL ISSUES FOUND!\n');
      console.log(`${critical.length} critical issue(s) detected:\n`);

      const grouped = this.groupByPackage(critical);
      for (const [pkg, items] of Object.entries(grouped)) {
        console.log(`❌ ${pkg}`);
        for (const item of items) {
          console.log(`   📁 ${item.file}`);
          console.log(`   📦 ${item.message}`);
          if (item.matchedMaliciousVersions.length > 0) {
            console.log(`   ⚠️  Could install: ${item.matchedMaliciousVersions.join(', ')}`);
          }
        }
        console.log('');
      }
    }

    if (warnings.length > 0) {
      console.log(`⚠️  ${warnings.length} warning(s) found:\n`);

      const grouped = this.groupByPackage(warnings);
      for (const [pkg, items] of Object.entries(grouped)) {
        console.log(`⚠️  ${pkg}`);
        if (items[0].allKnownMaliciousVersions.length > 0) {
          console.log(`   Known malicious: ${items[0].allKnownMaliciousVersions.join(', ')}`);
        }
        for (const item of items) {
          console.log(`   📁 ${item.file}`);
          console.log(`   📦 ${item.message}`);
        }
        console.log('');
      }
    }

    if (info.length > 0 && info.length < 10) {
      console.log(`ℹ️  ${info.length} informational finding(s):\n`);
      const grouped = this.groupByPackage(info);
      for (const [pkg, items] of Object.entries(grouped)) {
        console.log(`ℹ️  ${pkg} (${items.length} location(s))`);
      }
      console.log('');
    }

    this.printRecommendations(critical, warnings);
  }

  static formatJson(results) {
    return JSON.stringify(results, null, 2);
  }

  static groupByPackage(findings) {
    const grouped = {};
    for (const finding of findings) {
      if (!grouped[finding.package]) {
        grouped[finding.package] = [];
      }
      grouped[finding.package].push(finding);
    }
    return grouped;
  }

  static printRecommendations(critical, warnings) {
    console.log('⚠️  RECOMMENDED ACTIONS:\n');

    if (critical.length > 0) {
      console.log('🔴 CRITICAL - IMMEDIATE ACTION REQUIRED:');
      console.log('   1. DO NOT run npm install/update');
      console.log('   2. Check lock files for actual installed versions');
      console.log('   3. If malicious versions are installed:');
      console.log('      • Disconnect from network');
      console.log('      • Remove malicious packages');
      console.log('      • Rotate ALL credentials immediately');
      console.log('      • Check for unauthorized access');
      console.log('   4. Pin safe versions (remove ^ and ~ prefixes)');
      console.log('   5. Update to latest safe versions\n');
    }

    if (warnings.length > 0) {
      console.log('🟡 WARNING - VERIFICATION NEEDED:');
      console.log('   1. Verify installed versions in lock files');
      console.log('   2. Avoid running npm install without checking first');
      console.log('   3. Pin versions to prevent future issues');
      console.log('   4. Monitor package maintainer announcements\n');
    }

    console.log('💡 TIP: Lock files show actual installed versions');
    console.log('📖 More info: https://helixguard.ai/blog/malicious-sha1hulud-2025-11-24\n');
  }
}

module.exports = Reporter;
