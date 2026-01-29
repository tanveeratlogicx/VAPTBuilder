# Features Database JSON Integration Guide

## Overview

The `features-database.json` file provides a **structured, machine-readable database** of all 21 WordPress VAPT features. This document explains how to integrate and leverage this JSON file within the skill.

## 📍 File Location

```
.agent/skills/wordpress-vapt-expert/
└── resources/
    └── features-database.json
```

## 🎯 Value Proposition

### For the Antigravity Agent

1. **Structured Knowledge Access**
   - Parse JSON to understand features programmatically
   - Reference exact OWASP mappings and CWE identifiers
   - Access detailed verification steps for any feature
   - Retrieve severity and priority information

2. **Context-Aware Responses**
   - Generate implementations based on detailed descriptions
   - Include specific test methods from the database
   - Provide accurate remediation guidance
   - Reference correct implementation methods

3. **Dynamic Content Generation**
   - Create evidence documents with feature metadata
   - Generate test reports with proper categorization
   - Build comprehensive security documentation
   - Produce compliance mappings automatically

### For Scripts and Automation

1. **Automated Testing**
   - Scripts can read feature definitions
   - Generate test cases dynamically
   - Validate implementations against specifications
   - Create comprehensive test reports

2. **Evidence Generation**
   - Include exact feature descriptions
   - Reference OWASP/CWE standards automatically
   - Generate verification checklists
   - Create compliance documentation

3. **Feature Discovery**
   - Query available features programmatically
   - Filter by severity, category, or priority
   - Build dynamic menus and interfaces
   - Generate feature matrices

## 🔧 Integration Methods

### Method 1: Agent References JSON in SKILL.md

Add to SKILL.md:

```markdown
## Feature Database

A comprehensive JSON database of all features is available at:
`resources/features-database.json`

When implementing a feature, reference this database for:
- Exact feature descriptions
- OWASP/CWE mappings
- Detailed verification steps
- Implementation methods
- Remediation guidance
- Evidence requirements

Example agent usage:
1. Read features-database.json
2. Find feature by ID or name
3. Use verification_steps for testing
4. Include evidence_requirements in output
5. Reference OWASP/CWE in documentation
```

### Method 2: Scripts Read JSON Dynamically

The testing script can be enhanced to use JSON:

```bash
#!/bin/bash

# Load feature database
FEATURES_JSON="./resources/features-database.json"

# Parse JSON (requires jq)
get_feature_info() {
    local feature_id="$1"
    jq -r ".features[] | select(.id == \"$feature_id\")" "$FEATURES_JSON"
}

# Get verification steps for a feature
get_verification_steps() {
    local feature_id="$1"
    jq -r ".features[] | select(.id == \"$feature_id\") | .verification_steps[]" "$FEATURES_JSON"
}

# Example: Test SQL Injection using JSON data
test_sql_injection_from_json() {
    local steps=$(get_verification_steps "sql-injection")
    echo "$steps" | while read -r step; do
        echo "Executing: $step"
        # Execute the test step
    done
}
```

### Method 3: Evidence Generator Uses JSON

```bash
#!/bin/bash

generate_evidence_from_json() {
    local feature_id="$1"
    local feature_data=$(jq -r ".features[] | select(.id == \"$feature_id\")" "$FEATURES_JSON")
    
    # Extract fields
    local name=$(echo "$feature_data" | jq -r '.name')
    local description=$(echo "$feature_data" | jq -r '.description')
    local severity=$(echo "$feature_data" | jq -r '.severity')
    local owasp=$(echo "$feature_data" | jq -r '.owasp')
    local cwe=$(echo "$feature_data" | jq -r '.cwe')
    
    # Generate evidence document
    cat << EOF
# Security Implementation Evidence

## Feature: $name

**Severity:** $severity  
**OWASP:** $owasp  
**CWE:** $cwe

### Description
$description

### Verification Steps
$(echo "$feature_data" | jq -r '.verification_steps[]' | sed 's/^/- /')

### Evidence Requirements
$(echo "$feature_data" | jq -r '.evidence_requirements[]' | sed 's/^/- /')

EOF
}
```

### Method 4: WordPress Plugin Integration

For WordPress plugins that implement this skill:

```php
<?php
/**
 * Load and use features database
 */
class VAPT_Features_Database {
    
    private $features = [];
    
    public function __construct() {
        $json_file = plugin_dir_path(__FILE__) . 'resources/features-database.json';
        $json_data = file_get_contents($json_file);
        $data = json_decode($json_data, true);
        $this->features = $data['features'];
    }
    
    public function get_feature_by_id($feature_id) {
        foreach ($this->features as $feature) {
            if ($feature['id'] === $feature_id) {
                return $feature;
            }
        }
        return null;
    }
    
    public function get_features_by_severity($severity) {
        return array_filter($this->features, function($feature) use ($severity) {
            return $feature['severity'] === $severity;
        });
    }
    
    public function get_verification_steps($feature_id) {
        $feature = $this->get_feature_by_id($feature_id);
        return $feature ? $feature['verification_steps'] : [];
    }
}
```

## 📊 Use Cases

### Use Case 1: Dynamic Test Report Generation

```bash
# Generate comprehensive test report from JSON
generate_comprehensive_report() {
    echo "# WordPress VAPT Test Report"
    echo "Generated: $(date)"
    echo ""
    
    # Critical features
    echo "## Critical Severity Features"
    jq -r '.features[] | select(.severity == "critical") | "- \(.name) (\(.id))"' "$FEATURES_JSON"
    echo ""
    
    # Test each feature
    jq -r '.features[].id' "$FEATURES_JSON" | while read feature_id; do
        echo "### Testing: $(jq -r ".features[] | select(.id == \"$feature_id\") | .name" "$FEATURES_JSON")"
        # Run tests for this feature
        test_feature "$feature_id"
    done
}
```

### Use Case 2: Feature Implementation Checklist

```bash
# Generate implementation checklist
generate_checklist() {
    local priority="$1"  # critical_first, high_priority, etc.
    
    echo "# Implementation Checklist: $priority"
    echo ""
    
    jq -r ".implementation_priority.${priority}[]" "$FEATURES_JSON" | while read feature_id; do
        local feature_name=$(jq -r ".features[] | select(.id == \"$feature_id\") | .name" "$FEATURES_JSON")
        local severity=$(jq -r ".features[] | select(.id == \"$feature_id\") | .severity" "$FEATURES_JSON")
        
        echo "- [ ] $feature_name (Severity: $severity)"
    done
}
```

### Use Case 3: Compliance Documentation

```bash
# Generate OWASP compliance matrix
generate_compliance_matrix() {
    echo "# OWASP Top 10 2021 Compliance Matrix"
    echo ""
    echo "| OWASP Category | Covered Features | Severity |"
    echo "|----------------|------------------|----------|"
    
    jq -r '.features[].owasp' "$FEATURES_JSON" | sort -u | while read owasp_cat; do
        local features=$(jq -r ".features[] | select(.owasp == \"$owasp_cat\") | .name" "$FEATURES_JSON" | tr '\n' ', ')
        local max_severity=$(jq -r ".features[] | select(.owasp == \"$owasp_cat\") | .severity" "$FEATURES_JSON" | sort -u | head -1)
        
        echo "| $owasp_cat | $features | $max_severity |"
    done
}
```

### Use Case 4: Agent Query System

When the agent needs feature information:

```python
# Pseudocode for agent integration
def get_feature_implementation_details(feature_name):
    # Load JSON
    with open('resources/features-database.json', 'r') as f:
        data = json.load(f)
    
    # Find feature
    for feature in data['features']:
        if feature['name'].lower() in feature_name.lower():
            return {
                'description': feature['description'],
                'implementation_methods': feature['implementation_methods'],
                'verification_steps': feature['verification_steps'],
                'remediation': feature['remediation'],
                'owasp': feature['owasp'],
                'cwe': feature['cwe'],
                'severity': feature['severity']
            }
    
    return None

# Agent uses this when user asks:
# "Implement SQL Injection protection"
details = get_feature_implementation_details("SQL Injection")
# Agent now has all context needed for implementation
```

## 🛠️ JSON Query Examples

### Using jq Command-Line Tool

```bash
# Get all critical features
jq '.features[] | select(.severity == "critical") | .name' features-database.json

# Get implementation methods for a feature
jq '.features[] | select(.id == "sql-injection") | .implementation_methods' features-database.json

# Count features by severity
jq '[.features[] | .severity] | group_by(.) | map({severity: .[0], count: length})' features-database.json

# Get all features requiring .htaccess
jq '.features[] | select(.implementation_methods[] == ".htaccess") | .name' features-database.json

# Get verification steps for XSS
jq -r '.features[] | select(.id == "xss-protection") | .verification_steps[]' features-database.json

# Get features by OWASP category
jq '.features[] | select(.owasp | contains("A03:2021")) | .name' features-database.json

# Get testing tools
jq -r '.testing_tools[] | "\(.name): \(.command // .url)"' features-database.json
```

### Using Python

```python
import json

# Load database
with open('features-database.json', 'r') as f:
    db = json.load(f)

# Get critical features
critical = [f for f in db['features'] if f['severity'] == 'critical']

# Get features by category
injection_features = [f for f in db['features'] if f['category'] == 'Injection']

# Get implementation priority
priority = db['implementation_priority']['critical_first']

# Get verification steps
sql_feature = next(f for f in db['features'] if f['id'] == 'sql-injection')
verification_steps = sql_feature['verification_steps']
```

### Using JavaScript/Node.js

```javascript
const fs = require('fs');

// Load database
const db = JSON.parse(fs.readFileSync('features-database.json', 'utf8'));

// Get feature by ID
const getFeature = (id) => db.features.find(f => f.id === id);

// Get features by severity
const getBySeverity = (severity) => db.features.filter(f => f.severity === severity);

// Get implementation methods
const sqlInjection = getFeature('sql-injection');
console.log(sqlInjection.implementation_methods);

// Get all OWASP mappings
const owaspMappings = [...new Set(db.features.map(f => f.owasp))];
```

## 📝 Enhanced SKILL.md Integration

Add this section to SKILL.md:

```markdown
## Using the Features Database

The skill includes a comprehensive JSON database at `resources/features-database.json` containing:

### For Each Feature:
- **Unique ID**: Machine-readable identifier
- **Name**: Human-readable feature name
- **Description**: Detailed explanation
- **Category**: Feature category (Injection, Authentication, etc.)
- **Severity**: critical, high, medium, or low
- **Priority**: Implementation order (1-21)
- **OWASP Mapping**: OWASP Top 10 2021 reference
- **CWE Identifier**: Common Weakness Enumeration ID
- **Implementation Methods**: Required files (.htaccess, nginx, etc.)
- **Test Method**: Testing approach
- **Verification Steps**: Detailed testing instructions
- **Remediation**: Implementation guidance
- **Evidence Requirements**: What to document

### When Implementing a Feature:

1. Reference the JSON for complete feature details
2. Use verification_steps for testing
3. Include OWASP/CWE in documentation
4. Follow implementation_methods guidance
5. Collect evidence per evidence_requirements

### Example Usage:

When user requests "Implement SQL Injection protection":

1. Query JSON for feature ID "sql-injection"
2. Read description, severity (critical), OWASP (A03:2021)
3. Check implementation_methods: [".htaccess", "nginx", "wp-config.php", "functions.php"]
4. Provide code for all methods
5. Include verification_steps for testing
6. Document evidence_requirements
```

## 🔍 Benefits Summary

### For Agents
✅ Structured, queryable feature database  
✅ Exact OWASP/CWE references  
✅ Detailed verification procedures  
✅ Priority-based implementation order  
✅ Complete remediation guidance  

### For Scripts
✅ Dynamic test generation  
✅ Automated evidence creation  
✅ Compliance documentation  
✅ Feature discovery  
✅ Validation against specs  

### For Users
✅ Consistent feature information  
✅ Accurate compliance mapping  
✅ Comprehensive test coverage  
✅ Professional documentation  
✅ Audit-ready evidence  

## 🚀 Quick Start

1. **Place JSON file:**
   ```bash
   cp features-database.json .agent/skills/wordpress-vapt-expert/resources/
   ```

2. **Install jq (for bash scripts):**
   ```bash
   # Ubuntu/Debian
   sudo apt-get install jq
   
   # macOS
   brew install jq
   ```

3. **Test JSON access:**
   ```bash
   jq '.features[] | select(.severity == "critical") | .name' features-database.json
   ```

4. **Update scripts to use JSON:**
   - Modify vapt-test.sh to read verification steps
   - Enhance generate-evidence.sh to include feature metadata
   - Create new utilities for compliance reporting

## 📚 Additional Resources

- **jq Manual**: https://stedolan.github.io/jq/manual/
- **JSON Schema**: Consider adding schema validation
- **API Integration**: Build REST API around this data
- **Database Import**: Import into SQLite for complex queries

---

**Recommendation**: This JSON integration significantly enhances the skill's capabilities and should be included in the final package.

**File Size**: ~25KB (minimal overhead)  
**Dependencies**: None (jq optional for advanced bash usage)  
**Maintenance**: Update when features are added/modified
