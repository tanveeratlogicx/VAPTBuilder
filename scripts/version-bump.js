const fs = require('fs');
const path = require('path');

const versionType = process.argv[2]; // patch, minor, major
const packageJsonPath = path.join(__dirname, '../package.json');
const pluginFilePath = path.join(__dirname, '../vapt-builder.php');

if (!['patch', 'minor', 'major'].includes(versionType)) {
  console.error('Usage: node version-bump.js <patch|minor|major>');
  process.exit(1);
}

// 1. Read package.json
const packageJson = require(packageJsonPath);
const currentVersion = packageJson.version;
const versionParts = currentVersion.split('.').map(Number);

// 2. Increment Version
if (versionType === 'patch') versionParts[2]++;
if (versionType === 'minor') { versionParts[1]++; versionParts[2] = 0; }
if (versionType === 'major') { versionParts[0]++; versionParts[1] = 0; versionParts[2] = 0; }

const newVersion = versionParts.join('.');

console.log(`Bumping version from ${currentVersion} to ${newVersion}...`);

// 3. Update package.json
packageJson.version = newVersion;
fs.writeFileSync(packageJsonPath, JSON.stringify(packageJson, null, 2) + '\n');
console.log('✔ Updated package.json');

// 4. Update vapt-builder.php
let pluginContent = fs.readFileSync(pluginFilePath, 'utf8');

// Update Version Header
const headerRegex = /Version:\s+(\d+\.\d+\.\d+)/;
pluginContent = pluginContent.replace(headerRegex, `Version:           ${newVersion}`);

// Update Constant Definition
const defineRegex = /define\('VAPT_VERSION',\s+'(\d+\.\d+\.\d+)'\);/;
pluginContent = pluginContent.replace(defineRegex, `define('VAPT_VERSION', '${newVersion}');`);

fs.writeFileSync(pluginFilePath, pluginContent);
console.log('✔ Updated vapt-builder.php');

console.log(`Successfully bumped to version ${newVersion}`);
