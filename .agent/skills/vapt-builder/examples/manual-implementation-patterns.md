# Manual Implementation Patterns

## 1. Cloudflare WAF (Custom Rules)

**Syntax**: Expression Language
**Action**: Block / Challenge

### Example: Block XML-RPC
*   **Expression**: `(http.request.uri.path eq "/xmlrpc.php")`
*   **Action**: `Block`

### Example: Block SQL Injection Patterns in Query
*   **Expression**: `(http.request.uri.query contains "UNION SELECT") or (http.request.uri.query contains "information_schema")`
*   **Action**: `Block`

### Example: Geo-Block Specific Countries
*   **Expression**: `(ip.geoip.country in {"CN" "RU" "KP"})`
*   **Action**: `Managed Challenge`

---

## 2. Caddy (Caddyfile)

### Example: Security Headers
```caddy
header {
    X-Content-Type-Options "nosniff"
    X-Frame-Options "SAMEORIGIN"
    X-XSS-Protection "1; mode=block"
    Referrer-Policy "strict-origin-when-cross-origin"
}
```

### Example: Block Path (XML-RPC)
```caddy
@blocked {
    path /xmlrpc.php
    path *.sql
    path *.env
}
respond @blocked 403
```

### Example: Disable Directory Browsing
```caddy
file_server {
    browse off
}
```

---

## 3. Node.js (Express/Connect)

### Example: Security Headers (Helmet)
```javascript
const helmet = require('helmet');
app.use(helmet());
```

### Example: Manual Header Middleware
```javascript
app.use((req, res, next) => {
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  next();
});
```

### Example: Block Path
```javascript
app.use('/xmlrpc.php', (req, res) => {
  res.status(403).send('Forbidden');
});
```
