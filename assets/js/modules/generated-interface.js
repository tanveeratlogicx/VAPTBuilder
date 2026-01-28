// React Component to Render Generated Interfaces
// Version 3.0 - Global Driver & Probe Architecture
// Expects props: { feature, onUpdate }

(function () {
  const { createElement: el, useState, useEffect } = wp.element;
  const { Button, TextControl, ToggleControl, SelectControl, TextareaControl, Modal, Icon, Tooltip } = wp.components;
  const { __, sprintf } = wp.i18n;

  /**
   * PROBE REGISTRY: Global Verification Handlers
   */
  const PROBE_REGISTRY = {
    // 1. Header Probe: Verifies HTTP response headers
    check_headers: async (siteUrl, control, featureData, featureKey) => {
      const resp = await fetch(siteUrl + '?vapt_header_check=' + Date.now(), { method: 'GET', cache: 'no-store' });
      const headers = {};
      resp.headers.forEach((v, k) => { headers[k] = v; });
      console.log("[VAPT] Full Response Headers:", headers);

      const vaptEnforced = resp.headers.get('x-vapt-enforced');
      const enforcedFeature = resp.headers.get('x-vapt-feature');

      if (vaptEnforced === 'php-headers') {
        if (featureKey && enforcedFeature && enforcedFeature !== featureKey) {
          return { success: false, message: `Inconclusive: Headers are present, but enforced by another feature ('${enforcedFeature}'), not this one. Please disable the conflicting feature to test this one accurately.`, raw: headers };
        }
        return { success: true, message: `Plugin is actively enforcing headers (${vaptEnforced}).`, raw: headers };
      }

      return { success: false, message: `Security headers present, but NOT by this plugin. VAPT enforcement header missing.`, raw: headers };
    },

    // 2. Batch Probe: Verifies Rate Limiting (Sends 125% of RPM)
    spam_requests: async (siteUrl, control, featureData) => {
      try {
        let rpm = parseInt(featureData['rpm'] || featureData['rate_limit'], 10);

        if (isNaN(rpm)) {
          const limitKey = Object.keys(featureData).find(k => k.includes('limit') || k.includes('max') || k.includes('rpm'));
          if (limitKey) rpm = parseInt(featureData[limitKey], 10);
        }

        if (isNaN(rpm)) rpm = 5;

        console.log(`[VAPT] spam_requests Debug: rpm=${rpm}, load=${Math.ceil(rpm * 1.25)}, data=`, featureData);
        if (isNaN(rpm) || rpm <= 0) {
          throw new Error('Invalid rate limit configuration. RPM must be a positive number.');
        }

        const load = Math.ceil(rpm * 1.25);
        if (load > 1000) {
          console.warn('[VAPT] Warning: Rate limit test sending more than 1000 requests. This may impact server performance.');
        }

        try {
          const resetRes = await fetch(siteUrl + '/wp-json/vapt/v1/reset-limit', { method: 'POST', cache: 'no-store' });
          const resetJson = await resetRes.json();
          console.log('[VAPT] Rate limit reset debug:', resetJson);
        } catch (e) {
          console.warn('[VAPT] Failed to reset rate limit:', e);
        }

        const probes = [];
        for (let i = 0; i < load; i++) {
          probes.push(
            fetch(siteUrl + '?vapt_test_spike=' + i, { cache: 'no-store' })
              .then(r => ({ status: r.status, headers: r.headers }))
              .catch(err => {
                console.warn(`[VAPT] Request ${i} failed:`, err);
                return { status: 0, headers: new Headers(), error: err.message };
              })
          );
        }

        const responses = await Promise.all(probes);
        let debugInfo = '';
        let lastCount = -1;
        let traceInfo = '';

        let hasVaptHeader = false;
        const stats = responses.reduce((acc, r) => {
          acc[r.status] = (acc[r.status] || 0) + 1;

          if (r.headers.has('x-vapt-debug')) debugInfo = r.headers.get('x-vapt-debug');
          if (r.headers.has('x-vapt-count')) lastCount = r.headers.get('x-vapt-count');
          if (r.headers.has('x-vapt-trace')) traceInfo = r.headers.get('x-vapt-trace');
          if (r.headers.get('x-vapt-enforced') === 'php-rate-limit') hasVaptHeader = true;

          return acc;
        }, {});

        const errorCount = stats[500] || 0;
        const blocked = stats[429] || 0;
        const total = load;
        const successCount = stats[200] || 0;
        const debugMsg = `(Debug: ${debugInfo || 'None'}, Count: ${lastCount}, Trace: ${traceInfo || 'None'})`;

        const resultMeta = {
          total: total,
          accepted: successCount,
          blocked: blocked,
          errors: errorCount,
          details: debugMsg
        };

        if (blocked > 0 && hasVaptHeader) {
          return {
            success: true,
            message: `Rate limiter is ACTIVE. Security measures are working correctly.`,
            meta: resultMeta
          };
        }

        if (errorCount > 0) {
          return {
            success: false,
            message: `Server Error (500). Internal configuration or logic error detected.`,
            meta: resultMeta
          };
        }

        return {
          success: false,
          message: `Rate Limiter is NOT active. Traffic was not restricted.`,
          meta: resultMeta
        };
      } catch (err) {
        return {
          success: false,
          message: `Test Error: ${err.message}. Rate limit test could not complete.`,
          raw: { error: err.message, stack: err.stack }
        };
      }
    },

    // 3. Status Probe: Verifies specific file block (e.g., XML-RPC)
    block_xmlrpc: async (siteUrl, control, featureData, featureKey) => {
      const resp = await fetch(siteUrl + '/xmlrpc.php', { method: 'POST', body: '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName><params></params></methodCall>' });
      const vaptEnforced = resp.headers.get('x-vapt-enforced');
      const enforcedFeature = resp.headers.get('x-vapt-feature');

      if (vaptEnforced === 'php-xmlrpc') {
        if (featureKey && enforcedFeature && enforcedFeature !== featureKey) {
          return { success: false, message: `Inconclusive: XML-RPC is blocked by another VAPT feature ('${enforcedFeature}'). You must disable it there to verify this control independently.` };
        }
        return { success: true, message: `Plugin is actively blocking XML-RPC (${vaptEnforced}).` };
      }

      return { success: false, message: `XML-RPC is blocked (HTTP ${resp.status}), but NOT by this plugin. VAPT enforcement header missing.` };
    },

    // 4. Directory Probe: Verifies Indexing Block
    disable_directory_browsing: async (siteUrl, control, featureData, featureKey) => {
      const target = siteUrl + '/wp-content/uploads/';
      const resp = await fetch(target, { cache: 'no-store' });
      const text = await resp.text();
      const snippet = text.substring(0, 500);
      const vaptEnforced = resp.headers.get('x-vapt-enforced');
      const enforcedFeature = resp.headers.get('x-vapt-feature');

      if (vaptEnforced === 'php-dir') {
        if (featureKey && enforcedFeature && enforcedFeature !== featureKey) {
          return { success: false, message: `Inconclusive: Directory browsing blocked by '${enforcedFeature}'.`, raw: snippet };
        }
        return { success: true, message: `PASS: Plugin is actively blocking directory listing (${vaptEnforced}).`, raw: snippet };
      }

      return { success: false, message: `Directory browsing blocked (HTTP ${resp.status}), but NOT by this plugin. VAPT enforcement header missing.`, raw: snippet };
    },

    // 5. Null Byte Probe (and aliases)
    inject_null_unicode: async (siteUrl, control, featureData) => {
      return PROBE_REGISTRY.block_null_byte_injection(siteUrl, control, featureData);
    },
    block_null_byte_injection: async (siteUrl, control, featureData) => {
      const target = siteUrl + '/?vapt_test_param=safe&vapt_attack=test%00payload';
      const resp = await fetch(target, { cache: 'no-store' });
      const vaptEnforced = resp.headers.get('x-vapt-enforced');

      if (vaptEnforced === 'php-null-byte' || resp.status === 400) {
        return { success: true, message: `PASS: Null Byte Injection Blocked (HTTP ${resp.status}). Enforcer: ${vaptEnforced || 'Server'}` };
      }

      return { success: false, message: `FAIL: Null Byte Payload Accepted (HTTP ${resp.status}).` };
    },

    // 6. Version Hide Probe
    hide_wp_version: async (siteUrl, control, featureData) => {
      const resp = await fetch(siteUrl + '?vapt_version_check=1', { method: 'GET', cache: 'no-store' });
      const text = await resp.text();
      const vaptEnforced = resp.headers.get('x-vapt-enforced');

      const hasGenerator = text.toLowerCase().includes('name="generator" content="wordpress');

      if (!hasGenerator) {
        return { success: true, message: `Secure: WordPress generator tag is hidden.` };
      }

      return { success: false, message: `Vulnerable: WordPress generator tag is present in the page source.` };
    },

    // 7. Universal Payload Probe (Dynamic Real-World Testing)
    universal_probe: async (siteUrl, control, featureData, featureKey) => {
      const config = control.test_config || {};
      const method = config.method || 'GET';
      const path = config.path || '/';
      const params = config.params || {};
      const headers = config.headers || {};
      const body = config.body || null;
      const expectedStatus = config.expected_status;
      const expectedText = config.expected_text;
      const expectedHeaders = config.expected_headers;

      let url = siteUrl + path;
      if (method === 'GET' && Object.keys(params).length > 0) {
        const qs = new URLSearchParams(params).toString();
        url += (url.includes('?') ? '&' : '?') + qs;
      }

      const fetchOptions = {
        method: method,
        headers: headers,
        cache: 'no-store'
      };

      if (method !== 'GET' && body) {
        fetchOptions.body = typeof body === 'object' ? JSON.stringify(body) : body;
        if (typeof body === 'object' && !fetchOptions.headers['Content-Type']) {
          fetchOptions.headers['Content-Type'] = 'application/json';
        }
      } else if (method !== 'GET' && Object.keys(params).length > 0) {
        const formData = new URLSearchParams();
        for (const k in params) formData.append(k, params[k]);
        fetchOptions.body = formData;
        if (!fetchOptions.headers['Content-Type']) {
          fetchOptions.headers['Content-Type'] = 'application/x-www-form-urlencoded';
        }
      }

      const resp = await fetch(url, fetchOptions);
      const text = await resp.text();

      let isSecure = false;
      let statusMatches = false;
      let headerMatches = false;
      const code = resp.status;

      let expectedStatusArray = [];
      if (expectedStatus) {
        expectedStatusArray = Array.isArray(expectedStatus)
          ? expectedStatus.map(s => parseInt(s))
          : [parseInt(expectedStatus)];
      }

      if (expectedStatusArray.length > 0) {
        statusMatches = expectedStatusArray.includes(code);
      }

      if (expectedHeaders && typeof expectedHeaders === 'object') {
        headerMatches = true;
        const responseHeaders = {};
        resp.headers.forEach((v, k) => { responseHeaders[k.toLowerCase()] = v; });

        for (const [key, expectedValue] of Object.entries(expectedHeaders)) {
          const actualValue = responseHeaders[key.toLowerCase()];
          if (!actualValue || actualValue !== expectedValue) {
            headerMatches = false;
            break;
          }
        }
      }

      const expectsBlock = expectedStatusArray.length > 0 && expectedStatusArray.every(s => s >= 400);
      const expectsAllow = expectedStatusArray.includes(200);
      const hasHeaderCheck = expectedHeaders && typeof expectedHeaders === 'object';
      const enforcedFeature = resp.headers.get('x-vapt-feature');

      if (hasHeaderCheck) {
        isSecure = headerMatches && (code === 200 || expectsAllow || statusMatches);
      } else if (expectsBlock) {
        isSecure = statusMatches && code >= 400;
      } else if (expectsAllow) {
        isSecure = code === 200 && (expectedText ? text.includes(expectedText) : true);
      } else if (statusMatches) {
        isSecure = true;
      } else {
        isSecure = code >= 400;
      }

      if (isSecure && expectsBlock && featureKey && enforcedFeature && enforcedFeature !== featureKey) {
        isSecure = false;
        return {
          success: false,
          message: `Inconclusive: Request blocked by overlapping feature '${enforcedFeature}'. Disable it to verify this control.`,
          raw: `URL: ${url} | Status: ${code} | Enforcer: ${enforcedFeature} vs ${featureKey}`
        };
      }

      let message = '';
      if (isSecure) {
        if (hasHeaderCheck && headerMatches) {
          message = `Protection Headers Present (HTTP ${code}). All expected headers verified.`;
        } else if (expectsBlock && statusMatches) {
          message = `Attack Blocked (HTTP ${code}). Expected block code (${expectedStatus}).`;
        } else if (expectsAllow && code === 200) {
          message = `Normal Response (HTTP ${code}) with protection indicators.`;
        } else {
          message = `Expected Response Received (HTTP ${code}).`;
        }
      } else {
        if (code === 200 && expectsBlock) {
          message = `Attack Accepted (HTTP 200). Expected Block (${expectedStatus}).`;
        } else if (hasHeaderCheck && !headerMatches) {
          if (expectsBlock && statusMatches) {
            isSecure = true;
            message = `PASS: Request was blocked (HTTP ${code}). Note: VAPT enforcement header is missing, indicating a Server-Level block (e.g., .htaccess or Firewall) instead of PHP.`;
          } else {
            message = `Missing Protection Headers (HTTP ${code}). Verification failed.`;
          }
        } else if (statusMatches === false && expectedStatus) {
          message = `Mismatch: Got HTTP ${code}, expected ${expectedStatus}.`;
        } else {
          message = `Unexpected Response (HTTP ${code}). Could not verify security.`;
        }
      }

      return {
        success: isSecure,
        message: message,
        raw: `URL: ${url} | Status: ${code} | Expected: ${expectedStatus || 'N/A'}`
      };
    },

    // 8. Default Generic Probe
    default: async (siteUrl, control) => {
      const resp = await fetch(siteUrl + '?vapt_ping=1');
      return { success: resp.ok, message: `Probe result: HTTP ${resp.status}` };
    }
  };

  const TestRunnerControl = ({ control, featureData, featureKey }) => {
    const [status, setStatus] = useState('idle');
    const [result, setResult] = useState(null);

    const runTest = async () => {
      setStatus('running');
      setResult(null);

      const { test_logic } = control;
      const siteUrl = window.location.origin;
      const handler = PROBE_REGISTRY[test_logic] || PROBE_REGISTRY['default'];

      try {
        const timeoutPromise = new Promise((_, reject) =>
          setTimeout(() => reject(new Error('Test timeout after 30 seconds')), 30000)
        );
        const handlerPromise = handler(siteUrl, control, featureData, featureKey);
        const res = await Promise.race([handlerPromise, timeoutPromise]);

        if (res && typeof res === 'object') {
          setStatus(res.success ? 'success' : 'error');
          setResult(res);
        } else {
          throw new Error('Invalid test result format');
        }
      } catch (err) {
        setStatus('error');
        setResult({ success: false, message: `Error: ${err.message}` });
      }
    };

    const handleClick = () => {
      if (status !== 'idle' && result) {
        setResult(null);
        setStatus('idle');
      } else {
        runTest();
      }
    };

    let rpmValue = parseInt(featureData['rpm'] || featureData['rate_limit'], 10);
    if (isNaN(rpmValue)) {
      const limitKey = Object.keys(featureData).find(k => k.includes('limit') || k.includes('max') || k.includes('rpm'));
      if (limitKey) rpmValue = parseInt(featureData[limitKey], 10);
    }
    if (isNaN(rpmValue)) rpmValue = 5;

    const loadValue = Math.ceil(rpmValue * 1.25);
    const displayLabel = control.test_logic === 'spam_requests'
      ? control.label.replace(/\(\s*\d+.*\)/g, '').trim() + ` (${loadValue} requests)`
      : control.label;

    return el('div', { className: 'vapt-test-runner', style: { padding: '15px', background: '#f8fafc', border: '1px solid #e2e8f0', borderRadius: '6px', marginBottom: '10px' } }, [
      el('div', { style: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '2px' } }, [
        el('strong', { style: { fontSize: '12px', color: '#334155' } }, displayLabel),
        el(Button, { isSecondary: true, isSmall: true, isBusy: status === 'running', onClick: handleClick, disabled: status === 'running' }, 'Run Verify')
      ]),
      control.help && el('p', { style: { margin: '2px 0 0', fontSize: '11px', color: '#64748b', opacity: 0.8 } }, control.help),

      status !== 'idle' && status !== 'running' && result && el('div', {
        style: {
          marginTop: '10px',
          padding: '12px',
          background: status === 'success' ? '#f0fdf4' : '#fef2f2',
          border: `1px solid ${status === 'success' ? '#bbf7d0' : '#fecaca'}`,
          borderRadius: '6px',
          fontSize: '13px',
          color: status === 'success' ? '#166534' : '#991b1b'
        }
      }, [
        el('div', { style: { fontWeight: '700', marginBottom: '8px' } }, status === 'success' ? '✅ SUCCESS' : '❌ FAILURE'),
        el('div', { style: { marginBottom: '8px' } }, result.message),

        result.meta && el('div', { style: { background: 'rgba(255,255,255,0.5)', padding: '10px', borderRadius: '4px', border: '1px solid rgba(0,0,0,0.05)' } }, [
          el('div', { style: { display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px', fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.05em' } }, [
            el('div', { style: { color: '#059669' } }, [__('Accepted: '), el('strong', null, result.meta.accepted)]),
            el('div', { style: { color: '#dc2626' } }, [__('Blocked (429): '), el('strong', null, result.meta.blocked)]),
            el('div', { style: { color: '#4b5563' } }, [__('Errors: '), el('strong', null, result.meta.errors)]),
            el('div', { style: { color: '#4b5563' } }, [__('Total: '), el('strong', null, result.meta.total)])
          ]),
          el('div', { style: { marginTop: '8px', fontSize: '10px', opacity: 0.7, fontFamily: 'monospace' } }, result.meta.details)
        ])
      ])
    ]);
  };

  const GeneratedInterface = ({ feature, onUpdate, isGuidePanel = false }) => {
    const schema = feature.generated_schema ? (typeof feature.generated_schema === 'string' ? JSON.parse(feature.generated_schema) : feature.generated_schema) : {};
    const currentData = feature.implementation_data ? (typeof feature.implementation_data === 'string' ? JSON.parse(feature.implementation_data) : feature.implementation_data) : {};
    const [localAlert, setLocalAlert] = useState(null);

    if (!schema || !schema.controls || !Array.isArray(schema.controls)) {
      return el('div', { style: { padding: '20px', textAlign: 'center', color: '#999', fontStyle: 'italic' } },
        __('No functional controls defined for this implementation.', 'vapt-builder')
      );
    }

    const handleChange = (key, value) => {
      const updated = { ...currentData, [key]: value };
      if (onUpdate) onUpdate(updated);
    };

    const renderControl = (control, index) => {
      const { type, label, key, help, options, rows, action } = control;
      const value = currentData[key] !== undefined ? currentData[key] : (control.default || '');
      const uniqueKey = key || `ctrl-${index}`;

      switch (type) {
        case 'test_action':
          return el(TestRunnerControl, { key: uniqueKey, control, featureData: currentData, featureKey: feature.key || feature.id });

        case 'button':
          return el('div', { key: uniqueKey, style: { marginBottom: '15px' } }, [
            el(Button, {
              isSecondary: true,
              onClick: () => {
                if (action === 'reset_validation_logs') setLocalAlert({ message: __('Reset signal sent.', 'vapt-builder'), type: 'success' });
              }
            }, label),
            help && el('p', { style: { margin: '5px 0 0', fontSize: '12px', color: '#666' } }, help)
          ]);

        case 'toggle':
          return el(ToggleControl, {
            key: uniqueKey, label, help,
            checked: !!value,
            onChange: (val) => handleChange(key, val)
          });

        case 'input':
          return el('div', { key: uniqueKey, style: { marginBottom: '15px', padding: '10px', background: '#f8fafc', border: '1px solid #e2e8f0', borderRadius: '4px' } }, [
            el(TextControl, {
              label: el('strong', null, label),
              help: help,
              value: value ? value.toString() : '',
              onChange: (val) => handleChange(key, val),
              __nextHasNoMarginBottom: true,
              __next40pxDefaultSize: true
            })
          ]);

        case 'select':
          return el(SelectControl, {
            key: uniqueKey, label, help,
            value: value,
            options: options || [],
            onChange: (val) => handleChange(key, val)
          });

        case 'textarea':
        case 'code':
          return el('div', { key: uniqueKey, style: { marginBottom: '10px' } }, [
            el('div', { style: { display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '4px' } }, [
              el('label', { style: { fontSize: '12px', fontWeight: '600', color: '#334155' } }, label),
              help && el(Tooltip, { text: help }, el(Icon, { icon: 'info-outline', size: 14, style: { color: '#94a3b8', cursor: 'help' } }))
            ]),
            el(TextareaControl, {
              value: value,
              rows: rows || (type === 'code' ? 4 : 3),
              onChange: (val) => handleChange(key, val),
              placeholder: value ? '' : 'No operational notes available.',
              __nextHasNoMarginBottom: true,
              style: type === 'code' ? { fontFamily: 'monospace', fontSize: '11px', background: '#f8fafc' } : { fontSize: '12px' }
            })
          ]);

        case 'header':
          return el('h3', { key: uniqueKey, style: { fontSize: '14px', fontWeight: '700', borderBottom: '1px solid #e2e8f0', paddingBottom: '6px', marginTop: '8px', marginBottom: '8px', color: '#1e293b' } }, label);

        case 'section':
          return el('h4', { key: uniqueKey, style: { fontSize: '11px', fontWeight: '700', textTransform: 'uppercase', color: '#64748b', marginTop: '12px', marginBottom: '6px', letterSpacing: '0.025em' } }, label);

        case 'risk_indicators':
          return el('div', { key: uniqueKey, style: { padding: '10px 0' } }, [
            label && el('strong', { style: { display: 'block', fontSize: '11px', color: '#991b1b', marginBottom: '5px', textTransform: 'uppercase' } }, label),
            el('ul', { style: { margin: 0, paddingLeft: '18px', color: '#b91c1c', fontSize: '12px', listStyleType: 'disc' } },
              (control.risks || control.items || []).map((r, i) => el('li', { key: i, style: { marginBottom: '4px' } }, r)))
          ]);

        case 'assurance_badges':
          return el('div', { key: uniqueKey, style: { display: 'flex', gap: '8px', flexWrap: 'wrap', padding: '10px 0', marginTop: '10px', borderTop: '1px solid #fed7aa' } },
            (control.badges || control.items || []).map((b, i) => el('span', { key: i, style: { display: 'flex', alignItems: 'center', background: '#ffffff', color: '#166534', padding: '4px 10px', borderRadius: '15px', fontSize: '12px', border: '1px solid #bbf7d0', fontWeight: '600', boxShadow: '0 1px 2px rgba(0,0,0,0.05)' } }, [
              el('span', { style: { marginRight: '6px', fontSize: '14px' } }, '🛡️'),
              b
            ]))
          );

        case 'test_checklist':
        case 'evidence_list':
          return el('div', { key: uniqueKey, style: { marginBottom: '10px' } }, [
            label && el('strong', { style: { display: 'block', fontSize: '12px', color: '#334155', marginBottom: '6px' } }, label),
            el('ol', { style: { margin: 0, paddingLeft: '20px', color: '#475569', fontSize: '12px' } },
              (control.items || control.tests || control.checklist || control.evidence || []).map((item, i) => el('li', { key: i, style: { marginBottom: '4px' } }, item)))
          ]);

        case 'info':
        case 'html':
          return el('div', { key: uniqueKey, style: { padding: '8px 12px', background: '#f0f9ff', borderLeft: '3px solid #0ea5e9', fontSize: '11px', color: '#0c4a6e', marginBottom: '8px', lineHeight: '1.4' }, dangerouslySetInnerHTML: { __html: control.content || control.html || label } });

        case 'warning':
        case 'alert':
          return el('div', { key: uniqueKey, style: { padding: '10px', background: '#fff7ed', borderLeft: '3px solid #f97316', fontSize: '12px', color: '#7c2d12', marginBottom: '10px' }, dangerouslySetInnerHTML: { __html: label || control.content } });

        case 'remediation_steps':
        case 'evidence_uploader':
          return null;

        default:
          return null;
      }
    };

    const verificationTypes = ['verification_action', 'automated_test', 'risk_indicators', 'assurance_badges'];
    const guideTypes = ['test_checklist', 'evidence_list', 'remediation_steps', 'evidence_uploader'];

    const mainControls = schema.controls.filter(c => {
      const isVerification = verificationTypes.includes(c.type);
      const isGuide = guideTypes.includes(c.type);

      if (isGuidePanel) {
        return isGuide;
      } else {
        if (isVerification || isGuide) return false;

        if (c.type === 'section') {
          const label = (c.label || '').toLowerCase();
          const redundantLabels = [
            'verification',
            'automated verification',
            'functional verification',
            'manual verification guidelines',
            'threat coverage',
            'verification & assurance'
          ];
          if (redundantLabels.some(rl => label.includes(rl))) return false;
        }
        return true;
      }
    });

    const riskControls = schema.controls.filter(c => c.type === 'risk_indicators');
    const badgeControls = schema.controls.filter(c => c.type === 'assurance_badges');
    const otherVerificationControls = schema.controls.filter(c =>
      verificationTypes.includes(c.type) &&
      c.type !== 'risk_indicators' &&
      c.type !== 'assurance_badges' &&
      c.type !== 'verification_action' &&
      c.type !== 'automated_test'
    );

    const getBadgeIcon = (text) => {
      const t = (text || '').toString().toLowerCase();
      if (t.includes('prevent') || t.includes('block')) return '🛡️';
      if (t.includes('detect') || t.includes('log')) return '👁️';
      if (t.includes('limit') || t.includes('rate')) return '⚡';
      if (t.includes('secure') || t.includes('safe')) return '🔒';
      if (t.includes('complian') || t.includes('audit')) return '📋';
      return '✅';
    };

    return el('div', { className: 'vapt-generated-interface', style: { display: 'flex', flexDirection: 'column', gap: '20px' } }, [

      el('div', { className: 'vapt-functional-panel', style: { background: '#fff', borderRadius: '8px', padding: '0' } }, [
        el('div', { style: { display: 'flex', flexDirection: 'column', gap: '15px' } }, mainControls.map(renderControl)),
      ]),

      (riskControls.length > 0 || otherVerificationControls.length > 0) && el('div', {
        className: 'vapt-threat-panel',
        style: {
          background: '#fff7ed',
          border: '1px solid #fed7aa',
          borderRadius: '8px',
          padding: '15px'
        }
      }, [
        el('h4', { style: { margin: '0 0 10px 0', fontSize: '12px', fontWeight: '700', textTransform: 'uppercase', color: '#9a3412' } }, __('Threat Coverage', 'vapt-builder')),
        riskControls.map(renderControl),
        otherVerificationControls.map(renderControl)
      ]),

      badgeControls.length > 0 && el('div', {
        className: 'vapt-badges-row',
        style: { display: 'flex', flexWrap: 'wrap', gap: '10px' }
      },
        badgeControls.map(c =>
          (c.badges || c.items || []).map((b, i) => {
            const label = typeof b === 'object' ? (b.label || JSON.stringify(b)) : b;
            return el('span', { key: i, style: { display: 'flex', alignItems: 'center', background: '#ffffff', color: '#166534', padding: '6px 12px', borderRadius: '20px', fontSize: '12px', border: '1px solid #bbf7d0', fontWeight: '600', boxShadow: '0 1px 2px rgba(0,0,0,0.05)' } }, [
              el('span', { style: { marginRight: '6px', fontSize: '14px' } }, getBadgeIcon(label)),
              label
            ]);
          }))
      ),

      localAlert && el(Modal, {
        title: localAlert.type === 'error' ? __('Error', 'vapt-builder') : __('Notice', 'vapt-builder'),
        onRequestClose: () => setLocalAlert(null),
        style: { maxWidth: '400px' }
      }, [
        el('div', { style: { display: 'flex', gap: '10px', alignItems: 'center', marginBottom: '15px' } }, [
          localAlert.type === 'success' && el(Icon, { icon: 'yes', size: 24, style: { color: 'green', background: '#dcfce7', borderRadius: '50%', padding: '4px' } }),
          el('p', { style: { fontSize: '14px', color: '#1f2937', margin: 0 } }, localAlert.message)
        ]),
        el('div', { style: { textAlign: 'right' } },
          el(Button, { isPrimary: true, onClick: () => setLocalAlert(null) }, __('OK', 'vapt-builder'))
        )
      ])

    ]);
  };

  window.VAPT_GeneratedInterface = GeneratedInterface;
})();
