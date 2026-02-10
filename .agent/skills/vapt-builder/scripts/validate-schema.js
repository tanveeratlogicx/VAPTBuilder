/* eslint-env node */

/**
 * Schema Validator for VAPTBuilder
 * Usage: node validate-schema.js <path-to-schema.json>
 */
const fs = require('fs');

const schemaPath = process.argv[2];

if (!schemaPath) {
  console.error("Usage: node validate-schema.js <path-to-schema.json>");
  process.exit(1);
}

try {
  const rawData = fs.readFileSync(schemaPath, 'utf8');
  const schema = JSON.parse(rawData);

  // 1. Root Structure Check
  if (!schema.controls || !Array.isArray(schema.controls)) {
    throw new Error("Missing or invalid 'controls' array.");
  }
  if (!schema.enforcement || typeof schema.enforcement !== 'object') {
    throw new Error("Missing or invalid 'enforcement' object.");
  }

  // 2. Enforcement Driver Check
  const validDrivers = ['htaccess', 'hook', 'nginx', 'iis', 'manual'];
  if (!validDrivers.includes(schema.enforcement.driver)) {
    throw new Error(`Invalid driver '${schema.enforcement.driver}'. Must be one of: ${validDrivers.join(', ')}`);
  }

  // 3. Mappings / Steps Check
  if (schema.enforcement.driver === 'manual') {
    if (!schema.enforcement.manual_steps || !Array.isArray(schema.enforcement.manual_steps) || schema.enforcement.manual_steps.length === 0) {
      throw new Error("Driver is 'manual', so 'manual_steps' array is required and cannot be empty.");
    }
  } else {
    // Native Drivers
    if (!schema.enforcement.mappings || Object.keys(schema.enforcement.mappings).length === 0) {
      throw new Error(`Driver '${schema.enforcement.driver}' requires 'mappings' object.`);
    }

    // 4. Controls & Keys Check (Only for mapped drivers)
    const controlKeys = schema.controls.map(c => c.key);
    const mappingKeys = Object.keys(schema.enforcement.mappings);

    // Ensure every mapping key exists as a control
    mappingKeys.forEach(mKey => {
      if (!controlKeys.includes(mKey)) {
        console.warn(`WARNING: Mapping key '${mKey}' has no corresponding control.`);
      }
    });
  }

  // 5. Verification Check
  const hasTest = schema.controls.some(c => c.type === 'test_action');
  if (!hasTest) {
    console.warn("WARNING: No 'test_action' found. Verification is highly recommended.");
  }

  console.log("✅ Schema Validation Passed");

} catch (e) {
  console.error("❌ Validation Failed:", e.message);
  process.exit(1);
}
