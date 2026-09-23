#!/usr/bin/env node

/**
 * build.js - Vantage Extension Packager & Validator
 * Generates verified production distributions for:
 *  1. Firefox Add-ons Portal (AMO)
 *  2. Chrome Web Store (CWS)
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const ROOT_DIR = __dirname;
const DIST_DIR = path.join(ROOT_DIR, 'dist');
const FF_DIST = path.join(DIST_DIR, 'firefox');
const CHROME_DIST = path.join(DIST_DIR, 'chrome');

console.log('\x1b[36m%s\x1b[0m', '════════════════════════════════════════════════════════════');
console.log('\x1b[1m\x1b[35m%s\x1b[0m', '   🔭  Vantage - Multi-Store Extension Packager & Builder   ');
console.log('\x1b[36m%s\x1b[0m', '════════════════════════════════════════════════════════════\n');

// 1. Validate JavaScript syntax
console.log('\x1b[33m%s\x1b[0m', '[1/5] Validating JavaScript syntax...');
try {
  execSync('node -c dashboard.js && node -c background.js', { cwd: ROOT_DIR, stdio: 'inherit' });
  console.log('  \x1b[32m✔\x1b[0m JavaScript syntax validated successfully.');
} catch (err) {
  console.error('  \x1b[31m✖ JavaScript syntax error detected. Aborting build.\x1b[0m');
  process.exit(1);
}

// 2. Read manifests and check version
console.log('\n\x1b[33m%s\x1b[0m', '[2/5] Inspecting manifest configurations...');
const ffManifestRaw = fs.readFileSync(path.join(ROOT_DIR, 'manifest.json'), 'utf8');
const chromeManifestRaw = fs.readFileSync(path.join(ROOT_DIR, 'manifest.chrome.json'), 'utf8');

let ffManifest, chromeManifest;
try {
  ffManifest = JSON.parse(ffManifestRaw);
  chromeManifest = JSON.parse(chromeManifestRaw);
} catch (err) {
  console.error('  \x1b[31m✖ JSON parse error in manifest files:', err.message, '\x1b[0m');
  process.exit(1);
}

const version = ffManifest.version || '1.0.0';
console.log(`  \x1b[32m✔\x1b[0m Target Version: \x1b[1mv${version}\x1b[0m`);
console.log(`  \x1b[32m✔\x1b[0m Firefox ID: ${ffManifest.browser_specific_settings?.gecko?.id || 'none'}`);
console.log(`  \x1b[32m✔\x1b[0m Chrome Worker: ${chromeManifest.background?.service_worker || 'none'}`);

// 3. Clean and prepare dist directories
console.log('\n\x1b[33m%s\x1b[0m', '[3/5] Assembling unpacked release trees in dist/...');
fs.rmSync(DIST_DIR, { recursive: true, force: true });
fs.mkdirSync(FF_DIST, { recursive: true });
fs.mkdirSync(CHROME_DIST, { recursive: true });

const commonFiles = [
  'dashboard.html',
  'dashboard.css',
  'cytoscape.min.js',
  'dashboard.js',
  'background.js'
];

function copyFolderSync(from, to) {
  fs.mkdirSync(to, { recursive: true });
  fs.readdirSync(from).forEach(element => {
    const stat = fs.lstatSync(path.join(from, element));
    if (stat.isFile()) {
      fs.copyFileSync(path.join(from, element), path.join(to, element));
    } else if (stat.isDirectory()) {
      copyFolderSync(path.join(from, element), path.join(to, element));
    }
  });
}

// Populate Firefox tree
commonFiles.forEach(f => fs.copyFileSync(path.join(ROOT_DIR, f), path.join(FF_DIST, f)));
fs.writeFileSync(path.join(FF_DIST, 'manifest.json'), JSON.stringify(ffManifest, null, 2));
copyFolderSync(path.join(ROOT_DIR, 'icons'), path.join(FF_DIST, 'icons'));
console.log('  \x1b[32m✔\x1b[0m Firefox tree generated at: dist/firefox/');

// Populate Chrome tree
commonFiles.forEach(f => fs.copyFileSync(path.join(ROOT_DIR, f), path.join(CHROME_DIST, f)));
fs.writeFileSync(path.join(CHROME_DIST, 'manifest.json'), JSON.stringify(chromeManifest, null, 2));
copyFolderSync(path.join(ROOT_DIR, 'icons'), path.join(CHROME_DIST, 'icons'));
console.log('  \x1b[32m✔\x1b[0m Chrome tree generated at:  dist/chrome/');

// 4. Create Store Zip Bundles
console.log('\n\x1b[33m%s\x1b[0m', '[4/5] Creating store submission zip archives...');
const ffZipName = `vantage-firefox-v${version}.zip`;
const chromeZipName = `vantage-chrome-v${version}.zip`;
const ffZipPath = path.join(DIST_DIR, ffZipName);
const chromeZipPath = path.join(DIST_DIR, chromeZipName);

try {
  // Zip Firefox directory contents directly into root of zip
  execSync(`cd "${FF_DIST}" && zip -r -q "${ffZipPath}" ./*`, { stdio: 'inherit' });
  const ffStats = fs.statSync(ffZipPath);
  console.log(`  \x1b[32m✔\x1b[0m Created \x1b[1m${ffZipName}\x1b[0m (${(ffStats.size / 1024).toFixed(1)} KB)`);

  // Zip Chrome directory contents directly into root of zip
  execSync(`cd "${CHROME_DIST}" && zip -r -q "${chromeZipPath}" ./*`, { stdio: 'inherit' });
  const chromeStats = fs.statSync(chromeZipPath);
  console.log(`  \x1b[32m✔\x1b[0m Created \x1b[1m${chromeZipName}\x1b[0m (${(chromeStats.size / 1024).toFixed(1)} KB)`);
} catch (err) {
  console.error('  \x1b[31m✖ Error creating zip packages:\x1b[0m', err.message);
  process.exit(1);
}

// 5. Verification & Summary
console.log('\n\x1b[33m%s\x1b[0m', '[5/5] Verifying archive integrity...');
const ffList = execSync(`unzip -l "${ffZipPath}"`, { encoding: 'utf8' });
const chromeList = execSync(`unzip -l "${chromeZipPath}"`, { encoding: 'utf8' });

const requiredFiles = ['manifest.json', 'dashboard.html', 'cytoscape.min.js', 'dashboard.js', 'background.js', 'icons/icon-128.png'];
for (const file of requiredFiles) {
  if (!ffList.includes(file)) {
    console.error(`  \x1b[31m✖ Missing ${file} in Firefox zip!\x1b[0m`);
    process.exit(1);
  }
  if (!chromeList.includes(file)) {
    console.error(`  \x1b[31m✖ Missing ${file} in Chrome zip!\x1b[0m`);
    process.exit(1);
  }
}
console.log('  \x1b[32m✔\x1b[0m All critical manifest and core asset checkpoints verified.');

console.log('\n\x1b[32m%s\x1b[0m', '════════════════════════════════════════════════════════════');
console.log('\x1b[1m\x1b[32m%s\x1b[0m', '   🎉 BUILD COMPLETE - PACKAGES READY FOR DISTRIBUTION!    ');
console.log('\x1b[32m%s\x1b[0m', '════════════════════════════════════════════════════════════\n');

console.log('Artifacts generated:');
console.log(`  📦 Firefox AMO Bundle: \x1b[36mdist/${ffZipName}\x1b[0m`);
console.log(`  📦 Chrome CWS Bundle:  \x1b[36mdist/${chromeZipName}\x1b[0m`);
console.log(`  📂 Unpacked Firefox:   \x1b[36mdist/firefox/\x1b[0m`);
console.log(`  📂 Unpacked Chrome:    \x1b[36mdist/chrome/\x1b[0m\n`);
