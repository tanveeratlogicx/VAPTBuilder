# HOWTO: Using the VAPT Builder Skill

This guide explains how to use the VAPT Builder skill to implement security controls across different server environments.

## 1. Determine the Target Environment

Before generating any configuration, you must identify the server stack.

*   **Ask the User**: "Are you running on Apache, Nginx, IIS, or using Cloudflare?"
*   **Use Detection Script**: Run `php .agent/skills/vapt-builder/scripts/detect-server.php` to get a hint.
*   **Infer from Files**:
    *   `.htaccess` exists -> **Apache/Litespeed**
    *   `nginx.conf` or `*.conf` in root -> **Nginx**
    *   `web.config` exists -> **IIS**
    *   `Caddyfile` exists -> **Caddy**

## 2. Select the Correct Driver

| Environment | Driver ID | Output |
| :--- | :--- | :--- |
| **Apache / Litespeed** | `htaccess` | `.htaccess` rules (RewriteRule, Header, etc.) |
| **Nginx / OpenResty** | `nginx` | `add_header`, `location` directives |
| **IIS** | `iis` | `web.config` XML blocks |
| **Cloudflare** | `manual` | WAF Expression Language (in `manual_steps`) |
| **Caddy** | `manual` | Caddyfile directives (in `manual_steps`) |
| **Node.js** | `manual` | Middleware code (Helmet, Express) |

## 3. Generate the Schema

### Scenario A: Apache (Native)
Request: "Block XML-RPC"
Driver: `htaccess`

```json
{
  "enforcement": {
    "driver": "htaccess",
    "mappings": {
      "block_xmlrpc": "<Files xmlrpc.php>\nOrder Deny,Allow\nDeny from all\n</Files>"
    }
  }
}
```

### Scenario B: Nginx (Native)
Request: "Block XML-RPC"
Driver: `nginx`

```json
{
  "enforcement": {
    "driver": "nginx",
    "mappings": {
      "block_xmlrpc": "location = /xmlrpc.php { deny all; return 403; }"
    }
  }
}
```

### Scenario C: Cloudflare (Manual)
Request: "Block XML-RPC"
Driver: `manual`

```json
{
  "enforcement": {
    "driver": "manual",
    "manual_steps": [
      {
        "platform": "cloudflare",
        "description": "Create a Custom WAF Rule to block access to xmlrpc.php",
        "code": "(http.request.uri.path eq \"/xmlrpc.php\") action: block"
      }
    ]
  }
}
```

## 4. Validate

Always run the validation script before presenting the solution to the user:
`node .agent/skills/vapt-builder/scripts/validate-schema.js path/to/your/schema.json`

## 5. Verify (Post-Implementation)

Ensure your schema includes a `test_action` with `universal_probe` to verify the rule works.

```json
"test_config": {
  "method": "GET",
  "path": "/xmlrpc.php",
  "expected_status": 403
}
```
