// Global check-in for diagnostics - ABSOLUTE TOP
window.vaptScriptLoaded = true;

(function () {
  if (typeof wp === 'undefined') {
    console.error('VAPT Builder: "wp" global is missing!');
    return;
  }

  const { render, useState, useEffect, useMemo, Fragment, createElement: el } = wp.element || {};
  const {
    TabPanel, Panel, PanelBody, PanelRow, Button, Dashicon,
    ToggleControl, SelectControl, Modal, TextControl, Spinner,
    Notice, Placeholder, Dropdown, CheckboxControl, BaseControl, Icon,
    TextareaControl, Card, CardHeader, CardBody, Tooltip
  } = wp.components || {};
  // Global Settings from wp_localize_script (MOVED TO TOP v3.8.11)
  const settings = window.vaptSettings || {};
  const isSuper = settings.isSuper || false;

  // 🛡️ GLOBAL REST HOTPATCH (v3.8.16)
  // Replaces the global wp.apiFetch to catch 404s from any component (Core or Plugin)
  if (wp.apiFetch && !wp.apiFetch.__vapt_patched) {
    let localBroken = localStorage.getItem('vapt_rest_broken') === '1';
    const originalApiFetch = wp.apiFetch;

    const patchedApiFetch = (args) => {
      const getFallbackUrl = (pathOrUrl) => {
        if (!pathOrUrl) return null;
        const path = typeof pathOrUrl === 'string' && pathOrUrl.includes('/wp-json/')
          ? pathOrUrl.split('/wp-json/')[1]
          : pathOrUrl;
        const cleanHome = settings.homeUrl.replace(/\/$/, '');
        const cleanPath = path.replace(/^\//, '').split('?')[0];
        const queryParams = path.includes('?') ? '&' + path.split('?')[1] : '';
        return cleanHome + '/?rest_route=/' + cleanPath + queryParams;
      };

      // 🛡️ Pre-emptive Fallback if we already know REST is broken
      if (localBroken && (args.path || args.url) && settings.homeUrl) {
        const fallbackUrl = getFallbackUrl(args.path || args.url);
        if (fallbackUrl) {
          const fallbackArgs = Object.assign({}, args, { url: fallbackUrl });
          delete fallbackArgs.path;
          return originalApiFetch(fallbackArgs);
        }
      }

      return originalApiFetch(args).catch(err => {
        const status = err.status || (err.data && err.data.status);
        // 🛡️ Trigger fallback on 404 OR invalid_json (common when server returns HTML for 404)
        const isFallbackTrigger = status === 404 || err.code === 'rest_no_route' || err.code === 'invalid_json';

        if (isFallbackTrigger && (args.path || args.url) && settings.homeUrl) {
          const fallbackUrl = getFallbackUrl(args.path || args.url);
          if (!fallbackUrl) throw err;

          if (!localBroken) {
            console.warn('VAPT Builder: Switching to Pre-emptive Mode (Silent) for REST API.');
            localBroken = true;
            localStorage.setItem('vapt_rest_broken', '1');
          }

          const fallbackArgs = Object.assign({}, args, { url: fallbackUrl });
          delete fallbackArgs.path;
          return originalApiFetch(fallbackArgs);
        }
        throw err;
      });
    };

    // Copy properties like .use, .createNonceMiddleware, etc.
    Object.keys(originalApiFetch).forEach(key => {
      patchedApiFetch[key] = originalApiFetch[key];
    });
    patchedApiFetch.__vapt_patched = true;
    wp.apiFetch = patchedApiFetch;
  }

  const apiFetch = wp.apiFetch;
  const { __, sprintf } = wp.i18n || {};

  // Error Boundary Component
  class ErrorBoundary extends wp.element.Component {
    constructor(props) {
      super(props);
      this.state = { hasError: false, error: null, errorInfo: null };
    }

    static getDerivedStateFromError(error) {
      return { hasError: true, error };
    }

    componentDidCatch(error, errorInfo) {
      console.error("VAPT React Error:", error, errorInfo);
      this.setState({ errorInfo });
    }

    render() {
      if (this.state.hasError) {
        return el('div', { className: 'notice notice-error inline', style: { padding: '20px', margin: '20px' } }, [
          el('h3', null, 'Something went wrong rendering the VAPT Builder Dashboard.'),
          el('details', { style: { whiteSpace: 'pre-wrap', marginTop: '10px' } },
            this.state.error && this.state.error.toString(),
            el('br'),
            this.state.errorInfo && this.state.errorInfo.componentStack
          )
        ]);
      }
      return this.props.children;
    }
  }

  // Global Settings moved to top

  // Import Auto-Generator
  const Generator = window.VAPT_Generator;
  // Import Generated Interface UI
  const GeneratedInterface = window.VAPT_GeneratedInterface;

  if (!wp.element || !wp.components || !wp.apiFetch || !wp.i18n) {
    console.error('VAPT Builder: One or more WordPress dependencies are missing!');
    return;
  }

  // Shared Modal Components
  const VAPT_AlertModal = ({ isOpen, message, onClose, type = 'error' }) => {
    if (!isOpen) return null;
    return el(Modal, {
      title: type === 'error' ? __('Error', 'vapt-builder') : __('Notice', 'vapt-builder'),
      onRequestClose: onClose,
      style: { maxWidth: '400px' },
      className: 'vapt-alert-modal'
    }, [
      el('div', { style: { display: 'flex', gap: '15px', alignItems: 'flex-start', marginBottom: '20px' } }, [
        el(Icon, {
          icon: type === 'error' ? 'warning' : 'info',
          size: 32,
          style: {
            color: type === 'error' ? '#dc2626' : '#2563eb',
            background: type === 'error' ? '#fef2f2' : '#eff6ff',
            padding: '8px',
            borderRadius: '50%',
            flexShrink: 0
          }
        }),
        el('div', { style: { paddingTop: '4px' } }, [
          el('h3', { style: { margin: '0 0 8px 0', fontSize: '16px', fontWeight: 600 } }, type === 'error' ? 'Action Failed' : 'Notice'),
          el('p', { style: { margin: 0, fontSize: '14px', color: '#4b5563', lineHeight: '1.5' } }, message)
        ])
      ]),
      el('div', { style: { textAlign: 'right', borderTop: '1px solid #e5e7eb', paddingTop: '15px', marginTop: '10px' } },
        el(Button, { isPrimary: true, onClick: onClose }, __('OK', 'vapt-builder'))
      )
    ]);
  };

  const VAPT_ConfirmModal = ({ isOpen, message, onConfirm, onCancel, confirmLabel = __('Yes', 'vapt-builder'), isDestructive = false }) => {
    if (!isOpen) return null;
    return el(Modal, {
      title: __('Confirmation', 'vapt-builder'),
      onRequestClose: onCancel,
      className: 'vapt-confirm-modal-react'
    }, [
      el('div', { className: 'vapt-modal-body' }, [
        el('div', { style: { display: 'flex', gap: '15px', alignItems: 'flex-start', marginBottom: '20px' } }, [
          el(Icon, {
            icon: 'warning',
            size: 32,
            style: {
              color: '#d97706',
              background: '#fffbeb',
              padding: '8px',
              borderRadius: '50%',
              flexShrink: 0
            }
          }),
          el('div', { style: { paddingTop: '4px' } }, [
            el('h3', { style: { margin: '0 0 8px 0', fontSize: '16px', fontWeight: 600 } }, __('Are you sure?', 'vapt-builder')),
            el('p', { style: { margin: 0, fontSize: '14px', color: '#4b5563', lineHeight: '1.5', whiteSpace: 'pre-line' } }, message)
          ])
        ])
      ]),
      el('div', { style: { display: 'flex', justifyContent: 'flex-end', gap: '10px', borderTop: '1px solid #e5e7eb', paddingTop: '15px', marginTop: '10px' } }, [
        el(Button, { isSecondary: true, onClick: onCancel }, __('Cancel', 'vapt-builder')),
        el(Button, { isDestructive: isDestructive, isPrimary: !isDestructive, onClick: onConfirm }, confirmLabel)
      ])
    ]);
  };

  // History Modal Component
  const HistoryModal = ({ feature, updateFeature, onClose }) => {
    const [history, setHistory] = useState([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
      apiFetch({ path: `vapt/v1/features/${feature.key || feature.id}/history` })
        .then(res => {
          setHistory(res);
          setLoading(false);
        })
        .catch(() => setLoading(false));
    }, [feature.key || feature.id]);

    const [confirmState, setConfirmState] = useState(null);

    const resetHistory = () => {
      setConfirmState({
        message: sprintf(__('Are you sure you want to reset history for "%s"?\n\nThis will:\n1. Clear all history records.\n2. Reset status to "Draft".', 'vapt-builder'), feature.label),
        isDestructive: true,
        onConfirm: () => {
          setConfirmState(null);
          setLoading(true);
          updateFeature(feature.key || feature.id, {
            status: 'Draft',
            reset_history: true,
            has_history: false,
            history_note: 'History Reset by User',
            generated_schema: null,
            implementation_data: null,
            wireframe_url: '',
            include_verification_engine: 0,
            include_verification_guidance: 0
          }).then(() => {
            setLoading(false);
            onClose();
          });
        }
      });
    };

    return el(Modal, {
      id: 'vapt-history-modal',
      title: sprintf(__('History: %s', 'vapt-builder'), feature.name || feature.label),
      onRequestClose: onClose,
      className: 'vapt-history-modal'
    }, [
      el('div', { id: 'vapt-history-modal-actions', className: 'vapt-flex-between', style: { marginBottom: '10px' } }, [
        el('div', null), // Spacer
        el(Button, {
          id: 'vapt-btn-reset-history',
          isDestructive: true,
          isSmall: true,
          icon: 'trash',
          onClick: resetHistory,
          disabled: loading || history.length === 0
        }, __('Reset History & Status', 'vapt-builder'))
      ]),
      loading ? el(Spinner) : el('div', { id: 'vapt-history-modal-table-wrap' }, [
        history.length === 0 ? el('p', null, __('No history recorded yet.', 'vapt-builder')) :
          el('table', { className: 'wp-list-table widefat fixed striped' }, [
            el('thead', null, el('tr', null, [
              el('th', { style: { width: '120px' } }, __('Date', 'vapt-builder')),
              el('th', { style: { width: '100px' } }, __('From', 'vapt-builder')),
              el('th', { style: { width: '100px' } }, __('To', 'vapt-builder')),
              el('th', { style: { width: '120px' } }, __('User', 'vapt-builder')),
              el('th', null, __('Note', 'vapt-builder')),
            ])),
            el('tbody', null, history.map((h, i) => el('tr', { key: i }, [
              el('td', null, new Date(h.created_at).toLocaleString()),
              el('td', null, el('span', { className: `vapt-status-badge status-${h.old_status}` }, h.old_status)),
              el('td', null, el('span', { className: `vapt-status-badge status-${h.new_status}` }, h.new_status)),
              el('td', null, h.user_name || __('System', 'vapt-builder')),
              el('td', null, h.note || '-')
            ])))
          ])
      ]),
      el('div', { style: { marginTop: '20px', textAlign: 'right' } }, [
        el(Button, { isPrimary: true, onClick: onClose }, __('Close', 'vapt-builder'))
      ]),
      confirmState && el(VAPT_ConfirmModal, {
        isOpen: true,
        message: confirmState.message,
        isDestructive: confirmState.isDestructive,
        onConfirm: confirmState.onConfirm,
        onCancel: () => setConfirmState(null)
      })
    ]);
  };


  // Design/Schema Modal
  const DesignModal = ({ feature, onClose, updateFeature, designPromptConfig, setDesignPromptConfig, setIsPromptConfigModalOpen, selectedFile }) => {
    // Default prompt for guidance but still valid JSON (v3.6.11)
    const MEANINGFUL_DEFAULT = {
      "controls": [
        {
          "type": "header",
          "label": "Feature Configuration"
        },
        {
          "type": "toggle",
          "label": "Enable Feature",
          "key": "feat_enabled",
          "default": true
        }
      ],
      "enforcement": {
        "driver": "hook",
        "mappings": {
          "feat_enabled": "your_backend_hook_here"
        }
      },
      "_instructions": "Paste the AI-generated JSON here to replace this default."
    };

    const getInitialSchema = () => {
      if (!feature.generated_schema) return MEANINGFUL_DEFAULT;
      if (typeof feature.generated_schema === 'string') {
        try {
          const parsed = JSON.parse(feature.generated_schema);
          // Standardize empty/invalid schemas
          if (!parsed || (Array.isArray(parsed) && parsed.length === 0) || (typeof parsed === 'object' && Object.keys(parsed).length === 0)) {
            return MEANINGFUL_DEFAULT;
          }
          // If double-encoded, parse again
          if (typeof parsed === 'string') {
            const doubleParsed = JSON.parse(parsed);
            if (!doubleParsed || (Array.isArray(doubleParsed) && doubleParsed.length === 0)) return MEANINGFUL_DEFAULT;
            return doubleParsed;
          }
          return parsed;
        } catch (e) {
          return MEANINGFUL_DEFAULT;
        }
      }
      // Direct object check
      if (Array.isArray(feature.generated_schema) && feature.generated_schema.length === 0) return MEANINGFUL_DEFAULT;
      if (typeof feature.generated_schema === 'object' && Object.keys(feature.generated_schema).length === 0) return MEANINGFUL_DEFAULT;

      return feature.generated_schema;
    };

    const initialParsed = getInitialSchema();
    const defaultValue = JSON.stringify(initialParsed, null, 2);

    const [schemaText, setSchemaText] = useState(defaultValue);
    const [parsedSchema, setParsedSchema] = useState(initialParsed);
    const [localImplData, setLocalImplData] = useState(
      feature.implementation_data ? (typeof feature.implementation_data === 'string' ? JSON.parse(feature.implementation_data) : feature.implementation_data) : {}
    );
    const [isSaving, setIsSaving] = useState(false);
    const [saveStatus, setSaveStatus] = useState(null);

    // Toggles for Feature Display (v3.3.1)
    const [includeProtocol, setIncludeProtocol] = useState((feature.include_manual_protocol === undefined || feature.include_manual_protocol === null) ? true : feature.include_manual_protocol == 1);
    const [includeNotes, setIncludeNotes] = useState((feature.include_operational_notes === undefined || feature.include_operational_notes === null) ? true : feature.include_operational_notes == 1);

    // New: Hover state for paste logic
    const [isHoveringSchema, setIsHoveringSchema] = useState(false);

    // Handle "Replace on Hover" Paste Logic
    useEffect(() => {
      const handleGlobalPaste = (e) => {
        if (isHoveringSchema) {
          e.preventDefault();
          const text = (e.clipboardData || window.clipboardData).getData('text');
          if (text) {
            onJsonChange(text);
            setSaveStatus({ message: __('Content Replaced from Clipboard!', 'vapt-builder'), type: 'success' });
            setTimeout(() => setSaveStatus(null), 2000);
          }
        }
      };
      window.addEventListener('paste', handleGlobalPaste);
      return () => window.removeEventListener('paste', handleGlobalPaste);
    }, [isHoveringSchema]);

    // Prevent body scroll when modal is open
    useEffect(() => {
      const originalOverflow = document.body.style.overflow;
      document.body.style.overflow = 'hidden';
      return () => {
        document.body.style.overflow = originalOverflow;
      };
    }, []);

    // State for Alerts and Confirms
    const [alertState, setAlertState] = useState(null);
    const [confirmState, setConfirmState] = useState(null);

    // State for Remove Confirmation Modal
    const [isRemoveConfirmOpen, setIsRemoveConfirmOpen] = useState(false);

    // Handle real-time preview
    const onJsonChange = (val) => {
      setSchemaText(val);
      try {
        const parsed = JSON.parse(val);
        if (parsed && parsed.controls) setParsedSchema(parsed);
      } catch (e) {
        // Silent fail for preview while typing
      }
    };

    const handleSave = () => {
      try {
        // Attempt to clean common paste artifacts (Markdown code blocks & invisible chars)
        let cleanText = schemaText.trim();

        // Remove markdown code fences if present at start/end
        if (cleanText.startsWith('```')) {
          cleanText = cleanText.replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/, '');
        }

        // Replace non-breaking spaces with normal spaces
        cleanText = cleanText.replace(/\u00A0/g, ' ');
        // Remove zero-width spaces and other invisible formatting chars
        cleanText = cleanText.replace(/[\u200B\u200C\u200D\uFEFF]/g, '');

        const parsed = JSON.parse(cleanText);
        const controls = Array.isArray(parsed.controls) ? parsed.controls : [];
        const hasTestActions = controls.some(c => c.type === 'test_action');

        setIsSaving(true);
        updateFeature(feature.key || feature.id, {
          generated_schema: JSON.stringify(parsed),
          include_verification_engine: hasTestActions ? 1 : 0,
          include_verification_guidance: 1,
          include_manual_protocol: includeProtocol ? 1 : 0,
          include_operational_notes: includeNotes ? 1 : 0,
          implementation_data: JSON.stringify(localImplData)
        })
          .then(() => {
            setIsSaving(false);
            onClose();
          })
          .catch(() => setIsSaving(false));
      } catch (e) {
        console.error('VAPT Design Save Error:', e);
        if (e instanceof SyntaxError) {
          setAlertState({ message: sprintf(__('Invalid JSON format: %s. Check for hidden characters or syntax errors.', 'vapt-builder'), e.message) });
        } else {
          setAlertState({ message: sprintf(__('Execution Error: %s. Please report this to support.', 'vapt-builder'), e.message) });
        }
      }
    };

    const handleRemoveConfirm = () => {
      setIsSaving(true);
      updateFeature(feature.key || feature.id, {
        status: 'Draft',
        generated_schema: null,
        implementation_data: null,
        include_verification_engine: 0,
        include_verification_guidance: 0,
        reset_history: true,
        has_history: false
      })
        .then(() => {
          setIsSaving(false);
          setIsRemoveConfirmOpen(false); // Close confirm modal
          onClose(); // Close main modal
        })
        .catch(() => {
          setIsSaving(false);
          setIsRemoveConfirmOpen(false);
          setAlertState({ message: __('Failed to remove implementation.', 'vapt-builder') });
        });
    };

    const copyContext = () => {
      let contextJson = '';

      if (designPromptConfig) {
        contextJson = typeof designPromptConfig === 'string'
          ? designPromptConfig
          : JSON.stringify(designPromptConfig, null, 2);
      } else {
        const defaultTemplate = {
          "design_prompt": {
            "interface_type": "Interactive Security Assessment Interface",
            "schema_definition": "WordPress VAPT schema with standardized control fields",
            "id": "{{id}}",
            "title": "{{title}}",
            "description": "{{description}}",
            "severity": "{{severity}}",
            "category": "{{category}}",
            "compliance_references": "{{owasp}}",
            "cwe_reference": "{{cwe}}",
            "remediation_strategy": "{{remediation}}",
            "evidence_requirements": "{{evidence_requirements}}",
            "verification_steps": "{{verification_steps}}",
            "test_method": "{{test_method}}",
            "ui_components": {
              "primary_card": "{{automation_prompts.ai_ui}}",
              "test_checklist": "{{tests}}",
              "risk_indicators": "{{risks}}",
              "assurance_badges": "{{assurance}}",
              "evidence_list": "{{evidence}}"
            },
            "interface_layout": {
              "grid_structure": "Two-Column (Controls Left, Status Right)",
              "functional_blocks": [
                "Implementation Notes (Contextual Textarea)",
                "Manual Verification (Full-Width Protocol & Evidence Checklist)",
                "Automated Verification (Trigger Actions & Live Status)"
              ],
              "styling": "Standardized cards with subtle shadows, 24px padding, and clear hierarchy."
            },
            "automation_context": {
              "ai_check_prompt": "{{automation_prompts.ai_check}}",
              "ai_schema_fields": "{{automation_prompts.ai_schema}}"
            },
            "implementation_strategy": {
              "execution_driver": "Hybrid (Htaccess + PHP Hook Driver)",
              "enforcement_mechanism": "Intelligent automated selection based on target type.",
              "decision_matrix": {
                "driver: htaccess": "Use for physical files (.html, .txt, .php.bak, .env, xmlrpc.php) or server-wide blocking (Directory Browsing). Requires target: root.",
                "driver: hook": "Use for dynamic PHP logic, headers, or request interceptions (e.g. wp_head, init, login_init)."
              },
              "available_methods": [
                "limit_login_attempts - Enforces rate limiting (requires 'limit' or 'rate_limit' key)",
                "block_xmlrpc - Blocks XML-RPC requests (requires toggle)",
                "disable_directory_browsing - Blocks directory listing",
                "enable_security_headers - Injects security headers",
                "block_null_byte_injection - blocks null byte chars",
                "hide_wp_version - Hides version",
                "block_debug_exposure - Blocks debug.log access",
                "block_author_enumeration - Blocks author archives",
                "disable_xmlrpc_pingback - Disables XML-RPC pingbacks",
                "block_sensitive_files - Blocks readme.html, license.txt, etc."
              ],
              "data_binding": "Controls must use 'key' to bind to method arguments."
            },
            "verification_protocol": {
              "operational_notes": "Contextual help and operational guidance (Right Column)",
              "manual_verification": "Step-by-step human verification (Evidence Checklist)",
              "automated_verification": "Interactive test actions for real-time proof"
            },
            "threat_model": {
              "risks": "{{risks}}",
              "assurance_against": "{{assurance_against}}"
            },
            "raw_feature_context": "{{raw_json}}",
            "previous_implementation": "{{previous_schema}}"
          }
        };

        contextJson = JSON.stringify(defaultTemplate, null, 2);
      }

      // 1. Extract Development Guidance
      let displayInstruct = feature.dev_instruct || feature.devInstruct || '';
      if (!displayInstruct && feature.generated_schema) {
        try {
          const schema = typeof feature.generated_schema === 'string' ? JSON.parse(feature.generated_schema) : feature.generated_schema;
          if (schema && schema.instruction) {
            displayInstruct = schema.instruction;
          }
        } catch (e) { }
      }
      if (!displayInstruct) displayInstruct = 'No specific guidelines provided.';

      // 2. Extract Reference Code (v3.6.10)
      let referenceCode = '';
      if (feature.code_examples && Array.isArray(feature.code_examples)) {
        referenceCode = feature.code_examples.map(ex => {
          return `Language: ${ex.language || 'PHP'}\nDescription: ${ex.description || 'Implementation Logic'}\nCode:\n${ex.code}`;
        }).join('\n\n');
      }

      // Replace Placeholders
      const replaceAll = (str, key, val) => {
        const value = Array.isArray(val) ? val.join(', ') : (val || '');
        return str.split(`{{${key}}}`).join(value).split(`{${key}}`).join(value);
      };

      contextJson = replaceAll(contextJson, 'id', feature.id || 'N/A');
      contextJson = replaceAll(contextJson, 'title', feature.name || feature.label || feature.title || '');
      contextJson = replaceAll(contextJson, 'category', feature.category || 'General');
      contextJson = replaceAll(contextJson, 'description', feature.description || 'None provided');
      contextJson = replaceAll(contextJson, 'severity', feature.severity || 'Medium');
      contextJson = replaceAll(contextJson, 'remediation', Array.isArray(feature.remediation) ? feature.remediation.join('\n') : (feature.remediation || ''));
      contextJson = replaceAll(contextJson, 'assurance_against', Array.isArray(feature.assurance_against) ? feature.assurance_against.join(', ') : (feature.assurance_against || ''));
      contextJson = replaceAll(contextJson, 'assurance', Array.isArray(feature.assurance) ? feature.assurance.join(', ') : (feature.assurance || ''));
      contextJson = replaceAll(contextJson, 'tests', Array.isArray(feature.tests) ? feature.tests.join(', ') : (feature.tests || ''));
      contextJson = replaceAll(contextJson, 'evidence', Array.isArray(feature.evidence) ? feature.evidence.join(', ') : (feature.evidence || ''));
      contextJson = replaceAll(contextJson, 'schema_hints.fields', feature.schema_hints?.fields?.map(f => `${f.name} (${f.type})`).join(', '));
      contextJson = replaceAll(contextJson, 'test_method', feature.test_method || '');
      contextJson = replaceAll(contextJson, 'owasp', feature.owasp || '');
      contextJson = replaceAll(contextJson, 'cwe', feature.cwe || '');
      contextJson = replaceAll(contextJson, 'risks', Array.isArray(feature.risks) ? feature.risks.join(', ') : (feature.risks || ''));
      contextJson = replaceAll(contextJson, 'evidence_requirements', Array.isArray(feature.evidence_requirements) ? feature.evidence_requirements.join(', ') : (feature.evidence_requirements || ''));
      contextJson = replaceAll(contextJson, 'verification_steps', Array.isArray(feature.verification_steps) ? feature.verification_steps.join(', ') : (feature.verification_steps || ''));

      // Structural Alignment (v3.3.3)
      const rawContext = { ...feature };
      delete rawContext.generated_schema;
      delete rawContext.implementation_data;
      contextJson = replaceAll(contextJson, 'raw_json', JSON.stringify(rawContext, null, 2));
      contextJson = replaceAll(contextJson, 'previous_schema', feature.generated_schema || 'None');

      // Dynamic Substitution
      const prompts = feature.automation_prompts || {};
      contextJson = replaceAll(contextJson, 'automation_prompts.ai_ui', prompts.ai_ui || `Interactive JSON Schema for VAPT Workbench.`);
      contextJson = replaceAll(contextJson, 'automation_prompts.ai_check', prompts.ai_check || `PHP verification logic for ${feature.label || 'this feature'}.`);
      contextJson = replaceAll(contextJson, 'automation_prompts.ai_schema', prompts.ai_schema || `Essential schema fields for ${feature.label || 'this feature'}.`);

      // Assemble HYBRID PROMPT
      const finalPrompt = `
      --- ROLE & OBJECTIVE ---
      You are an Expert WordPress Security Engineer, UI Designer, and VAPT Specialist. Your core mandate is to implement security controls that adhere to VAPT and OWASP Top 10 risks and WordPress Coding Standards.

      I need you to generate a highly optimized JSON Schema for a 'Functional Workbench' interface for the following security feature:

      --- DESIGN CONTEXT (JSON) ---
      ${contextJson}
      --- 

      --- REFERENCE CODE ---
      ${referenceCode || 'No specific reference code provided in catalog.'}
      ---

      --- FEATURE-SPECIFIC REQUIREMENTS ---
      ${displayInstruct}
      ---

      --- INSTRUCTIONS & CRITICAL RULES ---
      1. **Response Format**: Provide ONLY a JSON block. No preamble or conversation.
      2. **Schema Structure**: You MUST include both 'controls' and 'enforcement' blocks.
      3. **Reference Code Usage**: You **MUST** first check the 'REFERENCE CODE' section.
         - If 'htaccess' rules are provided, use the 'htaccess' driver.
         - If PHP code is provided, use the 'hook' driver.
         - Map controls to the exact logic shown in the reference.
      4. **Control Properties (MANDATORY)**:
         - Every object in the 'controls' array ** MUST ** have a 'type' field.
         - ** Functional **: 'toggle', 'input', 'select', 'textarea', 'code', 'test_action', 'button', 'password'. (MUST HAVE 'key' & 'default').
         - ** Presentational **: 'info', 'alert', 'section', 'group', 'divider', 'html', 'header', 'label'. (NO 'key' required).
         - ** Rich UI **: 'risk_indicators', 'assurance_badges', 'test_checklist', 'evidence_list'. (NO 'key' required).
          - ** Optional **: 'visibility': { 'condition': 'has_content', 'fallback': 'hide' } - Use this to suppress empty informational blocks.
      5. ** JSON Skeleton **:
        \`\`\`json
      {
        "controls": [
          { "type": "header", "label": "Implementation" },
          { "type": "toggle", "label": "Enable Feature", "key": "feat_enabled", "default": true },
          { "type": "test_action", "label": "Verify Protection", "key": "verify_feat", "test_logic": "universal_probe", "test_config": { ... } }
        ],
        "enforcement": { 
          "driver": "hook", 
          "mappings": { "feat_enabled": "backend_method_name" } 
        },
        "// Alternative Htaccess Driver": {
          "enforcement": {
            "driver": "htaccess",
            "target": "root",
            "mappings": {
              "feat_enabled": "<FilesMatch \\"readme\\\\.html\\">\\\\nOrder allow,deny\\\\nDeny from all\\\\n</FilesMatch>"
            }
          }
        }
      }
      \`\`\`
      6. **Enforcement Drivers (INTELLIGENT SELECTION)**:
         - **MANDATORY**: Use 'htaccess' for any feature targeting physical files (e.g. readme.html, license.txt, xmlrpc.php, .env). PHP hooks CANNOT block these effectively on Apache.
         - Use 'hook' for dynamic logic, API interceptions, or header injections.
         - For 'htaccess', ALWAYS include 'target': 'root' in the enforcement block.
      7. **Visibility Overrides**:
         - INCLUDE 'test_checklist' and 'evidence_list' for verification.
         - ${includeNotes ? "INCLUDE a 'textarea' with key 'operational_notes' for Implementation Notes. Use visibility: { \"condition\": \"has_content\", \"fallback\": \"hide\" } to ensure it remains hidden if empty." : "EXCLUDE operational notes textarea."}
      8. **No Orphan Headers**: Do NOT include 'header' or 'section' controls if they are not followed by functional controls.

9. **Automated Verification (CRITICAL)**:
   - Use 'test_action' for verification buttons.
   - **MUST** include 'test_logic'. Valid options: 'universal_probe', 'check_headers', 'spam_requests', 'block_xmlrpc', 'disable_directory_browsing', 'hide_wp_version', 'block_null_byte_injection'.
   - For 'universal_probe', ensure 'test_config' is complete: { "method": "GET|POST", "path": "/", "expected_status": [200|403|429], "expected_text": "text_to_find" }.
   - If information is missing for a valid test, add an 'alert' control explaining exactly what is needed (e.g., "Missing endpoint path").
10. **Toggle Labels**: All 'toggle' controls MUST have a clear 'label' explaining what they enable/disable.
11. **Enforcement Logic**: Ensure 'enforcement.mappings' bind the functional keys (e.g., toggles) to the backend strategy.

Feature Name: ${feature.name || feature.label || feature.title}
Feature ID: ${feature.id || 'N/A'}
`;

      // Personalize Domain (v3.3.0)
      const currentDomain = (settings.currentDomain || window.location.hostname || 'hermasnet.local').split(':')[0];
      const placeholders = [/domain\.com/gi, /yourdomain\.com/gi, /example\.com/gi, /mysite\.com/gi];
      let personalizedPrompt = finalPrompt;
      placeholders.forEach(regex => {
        personalizedPrompt = personalizedPrompt.replace(regex, currentDomain);
      });

      const copyToClipboard = (text) => {
        if (navigator.clipboard) return navigator.clipboard.writeText(text);
        let textArea = document.createElement("textarea");
        textArea.value = text;
        document.body.appendChild(textArea);
        textArea.select();
        try { document.execCommand('copy'); } catch (err) { console.error('Copy failed', err); }
        document.body.removeChild(textArea);
        return Promise.resolve();
      };

      copyToClipboard(personalizedPrompt).then(() => {
        setSaveStatus({ message: __('Design Prompt copied!', 'vapt-builder'), type: 'success' });
        setTimeout(() => setSaveStatus(null), 3000);
      });
    };

    return el(Modal, {
      title: el('div', { className: 'vapt-design-modal-header' }, [
        el('span', null, sprintf(__('Design Implementation: %s', 'vapt-builder'), feature.label)),
        // Status Pill
        el('span', {
          style: {
            display: 'inline-flex',
            alignItems: 'center',
            marginLeft: '15px',
            padding: '3px 10px',
            borderRadius: '12px',
            fontSize: '11px',
            fontWeight: '600',
            color: '#fff',
            textTransform: 'uppercase',
            letterSpacing: '0.5px',
            verticalAlign: 'middle',
            background: (() => {
              const s = (feature.status || 'Draft').toLowerCase();
              if (s === 'develop') return '#10b981'; // Green
              if (s === 'test') return '#eab308'; // Yellowish Gold
              if (s === 'release') return '#f97316'; // Orange
              return '#94a3b8'; // Slate 400 (Draft)
            })(),
            boxShadow: '0 1px 2px rgba(0,0,0,0.1)'
          }
        }, feature.status || 'Draft'),
        el(Button, {
          isDestructive: true,
          isSmall: true,
          onClick: () => setIsRemoveConfirmOpen(true),
          disabled: isSaving || !feature.generated_schema,
          icon: 'trash'
        }, __('Remove Implementation', 'vapt-builder'))
      ]),
      onRequestClose: onClose,
      className: 'vapt-design-modal',
      id: 'vapt-design-modal-root'
    }, [
      saveStatus && el('div', {
        id: 'vapt-design-modal-banner',
        className: `vapt-modal-banner is-${saveStatus.type === 'error' ? 'error' : 'success'}`
      }, [
        el(Icon, { icon: saveStatus.type === 'error' ? 'warning' : 'yes', size: 20 }),
        saveStatus.message
      ]),

      el('form', {
        id: 'vapt-design-modal-form',
        onSubmit: (e) => e.preventDefault(),
        className: 'vapt-design-modal-inner-layout'
      }, [
        el('div', { id: 'vapt-design-modal-left-col' }, [

          el('div', { id: 'vapt-design-modal-actions', className: 'vapt-flex-row' }, [
            el(Button, { id: 'vapt-btn-copy-prompt', className: 'vapt-btn-flex-center', isSecondary: true, onClick: copyContext, icon: 'clipboard' }, __('Copy Design Prompt', 'vapt-builder')),
            el(Button, {
              isDestructive: true,
              icon: 'trash',
              onClick: () => {
                setConfirmState({
                  message: __('Are you sure you want to reset the schema? This will wash away any changes.', 'vapt-builder'),
                  isDestructive: true,
                  onConfirm: () => {
                    setConfirmState(null);
                    onJsonChange(JSON.stringify(defaultState, null, 2));
                    setSaveStatus({ message: __('Schema Reset!', 'vapt-builder'), type: 'success' });
                    setTimeout(() => setSaveStatus(null), 2000);
                  }
                });
              }
            }, __('Reset', 'vapt-builder'))
          ]),

          el('div', { id: 'vapt-design-modal-toggles', className: 'vapt-flex-col' }, [
            el(ToggleControl, {
              label: __('Include Manual Verification Protocol', 'vapt-builder'),
              checked: includeProtocol,
              onChange: setIncludeProtocol
            }),
            el(ToggleControl, {
              label: __('Include Operational Notes Section', 'vapt-builder'),
              checked: includeNotes,
              onChange: setIncludeNotes
            })
          ]),

          el('div', {
            id: 'vapt-design-modal-schema-editor',
            className: 'vapt-flex-col',
            onMouseEnter: () => setIsHoveringSchema(true),
            onMouseLeave: () => setIsHoveringSchema(false)
          }, [
            el('label', { id: 'vapt-schema-editor-label', className: 'vapt-label-uppercase' }, __('Interface JSON Schema', 'vapt-builder')),
            el('div', { id: 'vapt-schema-editor-hint', className: 'vapt-text-hint' }, __('Hover and Ctrl+V to replace content.', 'vapt-builder')),
            el('textarea', {
              id: 'vapt-schema-textarea',
              className: 'vapt-textarea-code',
              value: schemaText,
              onChange: (e) => onJsonChange(e.target.value),
              style: {
                background: isHoveringSchema ? '#f0fdf4' : '#fcfcfc'
              }
            })
          ]),

          (() => {
            let displayInstruct = feature.dev_instruct || feature.devInstruct || '';

            // FALLBACK: If dev_instruct is missing, try to extract from the generated schema string
            if (!displayInstruct && feature.generated_schema) {
              try {
                const schema = typeof feature.generated_schema === 'string' ? JSON.parse(feature.generated_schema) : feature.generated_schema;
                if (schema && schema.instruction) {
                  displayInstruct = schema.instruction;
                }
              } catch (e) {
                console.warn('VAPT: Failed to extract fallback instructions from schema', e);
              }
            }

            // Always show if we have something or a placeholder
            if (!displayInstruct) {
              displayInstruct = __('No specific development guidance available for this feature transition.', 'vapt-builder');
            }

            return el('div', { id: 'vapt-design-modal-guidance', className: 'vapt-flex-col', style: { marginBottom: '15px' } }, [
              el('label', { className: 'vapt-label-uppercase', style: { color: '#2271b1' } }, __('AI Development Guidance')),
              el('div', {
                className: 'vapt-guidance-box',
                style: {
                  background: '#f0f6fb',
                  borderLeft: '4px solid #2271b1',
                  padding: '12px',
                  fontSize: '12px',
                  maxHeight: '180px',
                  overflowY: 'auto',
                  whiteSpace: 'pre-wrap',
                  fontFamily: 'inherit'
                }
              }, displayInstruct)
            ]);
          })(),
        ]),

        el('div', { id: 'vapt-design-modal-right-col' }, [
          el('div', { className: 'vapt-design-modal-preview-header' }, [
            el('div', { className: 'vapt-flex-row', style: { gap: '8px' } }, [
              el(Icon, { icon: 'visibility', size: 16 }),
              el('strong', { className: 'vapt-preview-title' }, __('Live Implementation Preview'))
            ]),
            el('div', { className: 'vapt-flex-row' }, [
              el(Button, { isSecondary: true, isSmall: true, onClick: onClose }, __('Cancel', 'vapt-builder')),
              el(Button, { isPrimary: true, isSmall: true, onClick: handleSave, isBusy: isSaving }, __('Save & Deploy', 'vapt-builder'))
            ])
          ]),
          el('div', { className: 'vapt-design-modal-preview-body' }, [
            (() => {
              const schema = parsedSchema || { controls: [] };
              return el('div', { id: 'vapt-design-modal-preview-stack', className: 'vapt-flex-col' }, [
                el('div', { className: 'vapt-card-box' }, [
                  el('h4', { className: 'vapt-card-title' }, __('Functional Implementation')),
                  GeneratedInterface
                    ? el(GeneratedInterface, {
                      feature: { ...feature, generated_schema: schema, implementation_data: localImplData },
                      onUpdate: (newData) => setLocalImplData(newData)
                    })
                    : el('p', null, __('Loading Preview Interface...', 'vapt-builder'))
                ])
              ]);
            })()
          ])
        ])
      ]),

      isRemoveConfirmOpen && el(Modal, {
        title: __('Confirm Removal', 'vapt-builder'),
        onRequestClose: () => setIsRemoveConfirmOpen(false),
        style: { maxWidth: '450px' }
      }, [
        el('div', { style: { padding: '25px', textAlign: 'center' } }, [
          el(Icon, { icon: 'warning', size: 42, style: { color: '#dc2626', marginBottom: '15px' } }),
          el('h3', null, __('Remove Implementation?', 'vapt-builder')),
          el('p', { style: { fontSize: '13px', color: '#6b7280' } }, __('Are you sure? This cannot be undone.', 'vapt-builder')),
          el('div', { style: { display: 'flex', gap: '12px', justifyContent: 'center', marginTop: '20px' } }, [
            el(Button, { isSecondary: true, onClick: () => setIsRemoveConfirmOpen(false) }, __('Cancel', 'vapt-builder')),
            el(Button, { isDestructive: true, onClick: handleRemoveConfirm, isBusy: isSaving }, __('Yes, Remove It', 'vapt-builder'))
          ])
        ])
      ]),

      alertState && el(VAPT_AlertModal, {
        isOpen: true,
        message: alertState.message,
        type: alertState.type,
        onClose: () => setAlertState(null)
      }),
      confirmState && el(VAPT_ConfirmModal, {
        isOpen: true,
        message: confirmState.message,
        isDestructive: confirmState.isDestructive,
        onConfirm: confirmState.onConfirm,
        onCancel: () => setConfirmState(null)
      })
    ]);
  };

  // Prompt Configuration Modal
  const PromptConfigModal = ({ isOpen, onClose, feature, designPromptConfig, setDesignPromptConfig, selectedFile }) => {
    const [promptText, setPromptText] = useState(
      designPromptConfig ? (typeof designPromptConfig === 'string' ? designPromptConfig : JSON.stringify(designPromptConfig, null, 2)) : ''
    );

    const handleSave = () => {
      setDesignPromptConfig(promptText);
      onClose();
    };

    return el(Modal, {
      title: __('AI Design Prompt Configuration', 'vapt-builder'),
      onRequestClose: onClose,
      className: 'vapt-prompt-config-modal'
    }, [
      el('p', null, __('Customize the instructions sent to the AI for interface generation.', 'vapt-builder')),
      el(TextareaControl, {
        label: __('System Prompt / Context Template', 'vapt-builder'),
        value: promptText,
        onChange: setPromptText,
        rows: 20,
        style: { fontFamily: 'monospace', fontSize: '12px' }
      }),
      el('div', { style: { display: 'flex', justifyContent: 'flex-end', gap: '10px', marginTop: '15px' } }, [
        el(Button, { isSecondary: true, onClick: onClose }, __('Cancel', 'vapt-builder')),
        el(Button, { isPrimary: true, onClick: handleSave }, __('Save Configuration', 'vapt-builder'))
      ])
    ]);
  };

  // Field Mapping Modal Component
  const FieldMappingModal = ({ isOpen, onClose, fieldMapping, setFieldMapping, allKeys }) => {
    const handleAutoMap = () => {
      const newMapping = { ...fieldMapping };
      let mappedCount = 0;

      const findBestMatch = (keywords) => {
        for (const keyword of keywords) {
          // Exact match first, then partial
          const exact = allKeys.find(k => k.toLowerCase() === keyword);
          if (exact) return exact;

          const partial = allKeys.find(k => k.toLowerCase().includes(keyword));
          if (partial) return partial;
        }
        return '';
      };

      if (!newMapping.test_method) {
        const match = findBestMatch(['test_method', 'testmethod', 'testing_steps', 'method']);
        if (match) { newMapping.test_method = match; mappedCount++; }
      }

      if (!newMapping.verification_steps) {
        const match = findBestMatch(['verification_steps', 'verification', 'steps']);
        if (match) { newMapping.verification_steps = match; mappedCount++; }
      }

      if (!newMapping.verification_engine) {
        const match = findBestMatch(['verification_engine', 'verification_schema', 'json_schema', 'schema', 'engine']);
        if (match) { newMapping.verification_engine = match; mappedCount++; }
      }

      setFieldMapping(newMapping);
      if (mappedCount === 0) {
        alert(__('No new matching fields found.', 'vapt-builder'));
      }
    };

    return el(Modal, {
      title: __('Field Smart-Mapping Configuration', 'vapt-builder'),
      onRequestClose: onClose,
      className: 'vapt-mapping-modal'
    }, [
      el('div', { style: { padding: '5px' } }, [
        el('p', null, __('Map your raw data fields to VAPT Builder interactive components. When you enable a feature sub-type (like Test Method), the system will attempt to auto-populate from these source fields.', 'vapt-builder')),

        el('div', { style: { display: 'flex', flexDirection: 'column', gap: '15px', marginTop: '20px' } }, [
          el(SelectControl, {
            label: __('Source for "Test Method"', 'vapt-builder'),
            value: fieldMapping.test_method,
            options: [{ label: __('--- Select Source Field ---', 'vapt-builder'), value: '' }, ...allKeys.map(k => ({ label: k, value: k }))],


            onChange: (val) => setFieldMapping({ ...fieldMapping, test_method: val })
          }),
          el(SelectControl, {
            label: __('Source for "Verification Steps"', 'vapt-builder'),
            value: fieldMapping.verification_steps,
            options: [{ label: __('--- Select Source Field ---', 'vapt-builder'), value: '' }, ...allKeys.map(k => ({ label: k, value: k }))],
            onChange: (val) => setFieldMapping({ ...fieldMapping, verification_steps: val })
          }),
          el(SelectControl, {
            label: __('Source for "Verification Engine (JSON Schema)"', 'vapt-builder'),
            value: fieldMapping.verification_engine,
            options: [{ label: __('--- Select Source Field ---', 'vapt-builder'), value: '' }, ...allKeys.map(k => ({ label: k, value: k }))],
            onChange: (val) => setFieldMapping({ ...fieldMapping, verification_engine: val })
          })
        ]),

        el('div', { style: { marginTop: '25px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' } }, [
          el(Button, { isSecondary: true, onClick: handleAutoMap }, __('Auto Map', 'vapt-builder')),
          el(Button, { isPrimary: true, onClick: onClose }, __('Done', 'vapt-builder'))
        ])
      ])
    ]);
  };

  // Transition Note Modal Component
  const TransitionNoteModal = ({ transitioning, onConfirm, onCancel }) => {
    const [formValues, setFormValues] = useState({
      note: transitioning.note || '',
      dev_instruct: transitioning.dev_instruct || '',
      wireframeUrl: transitioning.wireframeUrl || ''
    });
    const [modalSaveStatus, setModalSaveStatus] = useState(null);

    return el(Modal, {
      title: sprintf(__('Transition to %s', 'vapt-builder'), transitioning.nextStatus),
      onRequestClose: onCancel,
      className: 'vapt-transition-modal',
      style: {
        width: '600px',
        maxWidth: '95%',
        maxHeight: '800px',
        overflow: 'hidden'
      }
    }, [
      el('div', {
        style: { height: '100%', display: 'flex', flexDirection: 'column' },
        onPaste: (e) => {
          if (transitioning.nextStatus !== 'Develop') return;
          const items = (e.clipboardData || e.originalEvent.clipboardData).items;
          for (let index in items) {
            const item = items[index];
            if (item.kind === 'file' && item.type.indexOf('image/') !== -1) {
              const blob = item.getAsFile();
              setModalSaveStatus({ message: __('Uploading pasted image...', 'vapt-builder'), type: 'info' });

              const formData = new FormData();
              formData.append('file', blob);
              formData.append('title', 'Pasted Wireframe - ' + transitioning.key);

              wp.apiFetch({
                path: 'vapt/v1/upload-media',
                method: 'POST',
                body: formData
              }).then(res => {
                setFormValues({ ...formValues, wireframeUrl: res.url });
                setModalSaveStatus({ message: __('Image Uploaded', 'vapt-builder'), type: 'success' });
              }).catch(err => {
                setModalSaveStatus({ message: __('Paste failed', 'vapt-builder'), type: 'error' });
              });
            }
          }
        }
      }, [
        el('div', { style: { flexGrow: 1, paddingBottom: '10px' } }, [
          el('p', { style: { fontWeight: '600', marginBottom: '10px' } }, sprintf(__('Moving "%s" to %s.', 'vapt-builder'), transitioning.key, transitioning.nextStatus)),

          el(TextareaControl, {
            label: __('Internal Transition Note', 'vapt-builder'),
            help: __('Reason for status change, logged in history.', 'vapt-builder'),
            value: formValues.note,
            onChange: (val) => setFormValues({ ...formValues, note: val }),
          }),

          transitioning.nextStatus === 'Develop' && el(Fragment, null, [
            el(TextareaControl, {
              label: __('Development Instructions (AI Guidance)', 'vapt-builder'),
              help: __('Instructions for the workbench designer (e.g. "Add a rate limiting slider").', 'vapt-builder'),
              value: formValues.dev_instruct,
              onChange: (val) => setFormValues({ ...formValues, dev_instruct: val }),
            }),
            el(TextControl, {
              label: __('Wireframe / Design URL', 'vapt-builder'),
              value: formValues.wireframeUrl,
              onChange: (val) => setFormValues({ ...formValues, wireframeUrl: val }),
              help: __('Paste image from clipboard directly into this modal.', 'vapt-builder')
            }),
            modalSaveStatus && el(Notice, {
              status: modalSaveStatus.type,
              isDismissible: false
            }, modalSaveStatus.message)
          ])
        ]),

        el('div', { style: { display: 'flex', justifyContent: 'flex-end', gap: '10px', paddingTop: '15px', borderTop: '1px solid #ddd' } }, [
          el(Button, { isSecondary: true, onClick: onCancel }, __('Cancel', 'vapt-builder')),
          el(Button, {
            isPrimary: true,
            onClick: () => onConfirm(formValues)
          }, sprintf(__('Confirm to %s', 'vapt-builder'), transitioning.nextStatus))
        ])
      ])
    ]);
  };

  // Backward Transition Warning Modal
  const BackwardTransitionModal = ({ isOpen, onConfirm, onCancel, type }) => {
    if (!isOpen) return null;

    let title = __('Warning', 'vapt-builder');
    let message = '';
    let confirmLabel = __('Confirm', 'vapt-builder');
    let isProduction = false;

    if (type === 'reset') {
      title = __('Reset to Draft?', 'vapt-builder');
      message = __('Warning: innovative "Clean Slate" protocol. Transitioning to Draft will **permanently delete** all implementation data, generated schemas, and history logs for this feature. This cannot be undone.', 'vapt-builder');
      confirmLabel = __('Confirm Reset (Wipe Data)', 'vapt-builder');
      checkboxLabel = __('I understand all history will be lost', 'vapt-builder');
    } else if (type === 'production_regression') {
      title = __('⚠️ Production Impact Warning', 'vapt-builder');
      message = __('You are demoting a **Released** feature. This feature may be active on multiple production sites.\n\nReverting to Test implies a potential defect that could impact live environments.', 'vapt-builder');
      confirmLabel = __('Confirm Production Regression', 'vapt-builder');
      checkboxLabel = __('I acknowledge this may impact live sites', 'vapt-builder');
      isProduction = true;
    } else {
      title = __('Confirm Regression', 'vapt-builder');
      // Added customization warning as requested
      message = __('Warning: You are moving this feature back to a previous stage within the cycle.\n\nPending verifications will be invalidated.\n**You may lose any customization applied to the Feature.**', 'vapt-builder');
      confirmLabel = __('Confirm Regression', 'vapt-builder');
      checkboxLabel = __('I acknowledge potential loss of customization', 'vapt-builder');
    }

    const [acknowledged, setAcknowledged] = useState(false);

    return el(Modal, {
      title: title,
      onRequestClose: onCancel,
      className: 'vapt-warning-modal',
      style: { maxWidth: '500px' }
    }, [
      el('div', { style: { padding: '20px' } }, [
        el('div', { style: { display: 'flex', gap: '15px', alignItems: 'flex-start' } }, [
          el(Icon, { icon: 'warning', size: 36, style: { color: isProduction ? '#d63638' : '#d97706' } }),
          el('div', null, [
            el('p', { style: { marginTop: 0, fontSize: '13px', lineHeight: '1.5', whiteSpace: 'pre-line' }, dangerouslySetInnerHTML: { __html: message.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>') } }),
            // Checkbox is now unconditional for all regressions
            el('div', { style: { marginTop: '15px', display: 'flex', alignItems: 'flex-start' } }, [
              el(CheckboxControl, {
                label: checkboxLabel,
                checked: acknowledged,
                onChange: setAcknowledged,
                style: { marginBottom: 0 }
              })
            ])
          ])
        ]),
        el('div', { style: { display: 'flex', justifyContent: 'flex-end', gap: '10px', marginTop: '25px' } }, [
          el(Button, { isSecondary: true, onClick: onCancel }, __('Cancel', 'vapt-builder')),
          el(Button, {
            isDestructive: true,
            disabled: !acknowledged, // Mandatory for all types
            onClick: onConfirm
          }, confirmLabel)
        ])
      ])
    ]);
  };

  // Lifecycle Indicator Component
  const LifecycleIndicator = ({ feature, onChange, onDirectUpdate }) => {
    const activeStep = feature.status;
    const [warningState, setWarningState] = useState(null); // { type, nextStatus }

    const steps = [
      { id: 'Draft', label: __('Draft', 'vapt-builder') },
      { id: 'Develop', label: __('Develop', 'vapt-builder') },
      { id: 'Test', label: __('Test', 'vapt-builder') },
      { id: 'Release', label: __('Release', 'vapt-builder') }
    ];

    const getStepValue = (status) => {
      const map = { 'Draft': 0, 'Develop': 1, 'Test': 2, 'Release': 3 };
      return map[status] || 0; // Default to 0 if unknown
    };

    const handleSelection = (nextStatus) => {
      const currentVal = getStepValue(activeStep);
      const nextVal = getStepValue(nextStatus);

      if (nextVal < currentVal) {
        // PCR: Backward Transition Warning
        let type = 'regression';
        if (nextStatus === 'Draft') type = 'reset';
        else if (activeStep === 'Release' && nextStatus === 'Test') type = 'production_regression';

        setWarningState({ type, nextStatus });
      } else {
        onChange(nextStatus);
      }
    };

    return el(Fragment, null, [
      el('div', { id: `vapt-lifecycle-controls-${feature.key}`, className: 'vapt-flex-row', style: { fontSize: '12px' } }, [
        ...steps.map((step) => {
          const isChecked = step.id === activeStep;
          return el('label', {
            id: `vapt-lifecycle-label-${feature.key}-${step.id}`,
            key: step.id,
            style: { cursor: 'pointer', color: isChecked ? '#2271b1' : 'inherit', fontWeight: isChecked ? '600' : 'normal' },
            className: 'vapt-flex-row'
          }, [
            el('input', {
              id: `vapt-lifecycle-radio-${feature.key}-${step.id}`,
              type: 'radio',
              name: `lifecycle_${feature.key || feature.id}_${Math.random()}`,
              checked: isChecked,
              onChange: () => handleSelection(step.id),
              style: { margin: 0 }
            }),
            step.label
          ]);
        })
      ]),
      warningState && el(BackwardTransitionModal, {
        isOpen: true,
        type: warningState.type,
        onCancel: () => setWarningState(null),
        onConfirm: () => {
          const status = warningState.nextStatus;
          setWarningState(null);

          if (onDirectUpdate) {
            const isReset = status === 'Draft';
            const updates = {
              status: status,
              history_note: isReset ? 'History Reset by User (Clean Slate)' : 'Regression Confirmed'
            };

            if (isReset) {
              updates.reset_history = true;
              updates.has_history = false;
              updates.generated_schema = null;
              updates.implementation_data = null;
              updates.wireframe_url = '';
              updates.include_verification_engine = 0;
              updates.include_verification_guidance = 0;
            }

            onDirectUpdate(feature.key || feature.id, updates);
          } else {
            onChange(status); // Fallback if prop not provided
          }
        }
      })
    ]);
  };

  const DomainFeatures = ({ domains = [], features = [], isDomainModalOpen, selectedDomain, setDomainModalOpen, setSelectedDomain, updateDomainFeatures, addDomain, deleteDomain, batchDeleteDomains, setConfirmState, selectedDomains = [], setSelectedDomains, dataFiles = [], selectedFile, onSelectFile }) => {
    const [newDomain, setNewDomain] = useState('');
    const [isWildcardNew, setIsWildcardNew] = useState(false);
    const [activeCategory, setActiveCategory] = useState('all');
    const [statusFilters, setStatusFilters] = useState(['draft', 'develop', 'test', 'release']);
    const [sortConfig, setSortConfig] = useState({ key: 'domain', direction: 'asc' });
    const [isEditModalOpen, setEditModalOpen] = useState(false);
    const [editDomainData, setEditDomainData] = useState({ id: '', domain: '', is_wildcard: false, is_enabled: true });
    const [viewFeaturesModalOpen, setViewFeaturesModalOpen] = useState(false);
    const [viewFeaturesModalDomain, setViewFeaturesModalDomain] = useState(null);

    const toggleDomainSelection = (id) => {
      const current = selectedDomains || [];
      if (current.includes(id)) {
        setSelectedDomains(current.filter(i => i !== id));
      } else {
        setSelectedDomains([...current, id]);
      }
    };

    const sortedDomains = useMemo(() => {
      const sortable = [...(domains || [])];
      if (sortConfig.key !== null) {
        sortable.sort((a, b) => {
          let valA = a[sortConfig.key];
          let valB = b[sortConfig.key];

          // Special handling for domain types (Wildcard vs Standard)
          if (sortConfig.key === 'is_wildcard') {
            valA = (valA === '1' || valA === true || valA === 1) ? 1 : 0;
            valB = (valB === '1' || valB === true || valB === 1) ? 1 : 0;
          }

          if (valA < valB) return sortConfig.direction === 'asc' ? -1 : 1;
          if (valA > valB) return sortConfig.direction === 'asc' ? 1 : -1;
          return 0;
        });
      }
      return sortable;
    }, [domains, sortConfig]);

    const requestSort = (key) => {
      let direction = 'asc';
      if (sortConfig.key === key && sortConfig.direction === 'asc') {
        direction = 'desc';
      }
      setSortConfig({ key, direction });
    };

    const SortIndicator = ({ column }) => {
      if (sortConfig.key !== column) return el(Dashicon, { icon: 'sort', size: 14, style: { opacity: 0.3, marginLeft: '5px' } });
      return el(Dashicon, {
        icon: sortConfig.direction === 'asc' ? 'arrow-up-alt2' : 'arrow-down-alt2',
        size: 14,
        style: { marginLeft: '5px', color: '#2271b1' }
      });
    };

    const filteredByStatus = useMemo(() => {
      return (features || []).filter(f => {
        // 1. Inactive File Visibility Check (Superadmin)
        if (isSuper && !f.is_from_active_file) {
          const s = f.status ? f.status.toLowerCase() : 'draft';
          if (s === 'draft' || s === 'default' || !s) return false;
        }

        const s = f.status ? f.status.toLowerCase() : 'draft';
        const normalized = (s === 'implemented') ? 'release' : s;
        return (statusFilters || []).includes(normalized);
      });
    }, [features, statusFilters]);

    const categories = useMemo(() => {
      const cats = [...new Set(filteredByStatus.map(f => f.category || 'Uncategorized'))].sort();
      return cats;
    }, [filteredByStatus]);

    const displayFeatures = useMemo(() => {
      const filtered = filteredByStatus || [];
      if (activeCategory === 'all') return filtered;
      return filtered.filter(f => (f.category || 'Uncategorized') === activeCategory);
    }, [filteredByStatus, activeCategory]);

    const featuresByCategory = useMemo(() => {
      const grouped = {};
      (displayFeatures || []).forEach(f => {
        const cat = f.category || 'Uncategorized';
        if (!grouped[cat]) grouped[cat] = [];
        grouped[cat].push(f);
      });
      // Sort categories to ensure consistent order
      const sortedResult = {};
      Object.keys(grouped).sort().forEach(key => {
        sortedResult[key] = grouped[key];
      });
      return sortedResult;
    }, [displayFeatures]);


    const domainStats = useMemo(() => {
      const doms = Array.isArray(domains) ? domains : [];
      return {
        total: doms.length,
        active: doms.filter(d => !(d.is_enabled === '0' || d.is_enabled === false || d.is_enabled === 0)).length,
        disabled: doms.filter(d => (d.is_enabled === '0' || d.is_enabled === false || d.is_enabled === 0)).length
      };
    }, [domains]);

    return el(PanelBody, { className: 'vapt-feature-panel', title: __('Domain Specific Features', 'vapt-builder'), initialOpen: true }, [
      // Summary Pill Row (Synced with Feature List)
      el('div', {
        style: {
          display: 'flex',
          gap: '15px',
          padding: '6px 15px',
          background: '#fff',
          border: '1px solid #dcdcde',
          borderRadius: '4px',
          marginBottom: '10px',
          alignItems: 'center',
          fontSize: '11px',
          color: '#333'
        }
      }, [
        el('span', { style: { fontWeight: '700', textTransform: 'uppercase', fontSize: '10px', color: '#666' } }, __('Summary:', 'vapt-builder')),
        el('span', { style: { fontWeight: '600', color: '#2271b1' } }, sprintf(__('Total Domains: %d', 'vapt-builder'), domainStats.total)),
        el('span', { style: { color: '#46b450', fontWeight: '700' } }, sprintf(__('Active: %d', 'vapt-builder'), domainStats.active)),
        el('span', { style: { color: '#d63638', fontWeight: '600' } }, sprintf(__('Disabled: %d', 'vapt-builder'), domainStats.disabled)),

        el('div', {
          style: {
            marginLeft: 'auto',
            display: 'flex',
            alignItems: 'center',
            gap: '12px',
            padding: '2px 0'
          }
        }, [
          el('span', { style: { fontWeight: '700', textTransform: 'uppercase', fontSize: '9px', color: '#64748b' } }, __('Data Sources:', 'vapt-builder')),
          el('div', { style: { display: 'flex', gap: '12px', flexWrap: 'wrap' } }, [
            // "All Data Files" Option (Only show for 3+ files)
            dataFiles.length >= 3 && el('label', {
              key: 'all-files',
              style: {
                display: 'flex',
                alignItems: 'center',
                gap: '4px',
                cursor: 'pointer',
                fontSize: '10px',
                fontWeight: (selectedFile || '').split(',').includes('__all__') ? '700' : '500',
                color: (selectedFile || '').split(',').includes('__all__') ? '#1e3a8a' : '#64748b'
              }
            }, [
              el('input', {
                type: 'checkbox',
                checked: (selectedFile || '').split(',').includes('__all__'),
                onChange: () => onSelectFile('__all__'),
                style: { margin: 0, width: '12px', height: '12px' }
              }),
              __('All Data Files', 'vapt-builder')
            ]),
            // Individual Files
            ...dataFiles.map(file => {
              const BASELINE_FILE = 'VAPT-Complete-Risk-Catalog-99.json';
              const isBaseline = file.value === BASELINE_FILE;
              const isAllSelected = (selectedFile || '').split(',').includes('__all__');
              const isChecked = isAllSelected || (selectedFile || '').split(',').includes(file.value) || isBaseline;

              return el('label', {
                key: file.value,
                style: {
                  display: 'flex',
                  alignItems: 'center',
                  gap: '4px',
                  cursor: isBaseline ? 'default' : 'pointer',
                  fontSize: '10px',
                  fontWeight: isChecked ? '700' : '500',
                  color: isChecked ? '#1e3a8a' : '#64748b',
                  opacity: (isBaseline && !isAllSelected) ? 0.7 : 1
                }
              }, [
                el('input', {
                  type: 'checkbox',
                  checked: isChecked,
                  disabled: isAllSelected || isBaseline,
                  onChange: () => onSelectFile(file.value),
                  style: { margin: 0, width: '12px', height: '12px' }
                }),
                file.label
              ]);
            })
          ])
        ])
      ]),

      el('div', {
        style: {
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          marginBottom: '10px'
        }
      }, [
        el('div', { key: 'add-domain-header', style: { fontSize: '11px', fontWeight: 700, color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.05em' } }, __('Add New Domain', 'vapt-builder'))
      ]),
      el('div', {
        key: 'add-domain-row',
        style: {
          marginBottom: '20px',
          display: 'flex',
          gap: '15px',
          alignItems: 'center',
          background: '#f8fafc',
          padding: '15px',
          borderRadius: '8px',
          border: '1px solid #e2e8f0'
        }
      }, [
        el('div', { style: { flex: 1 } }, [
          el(TextControl, {
            label: __('Domain Name', 'vapt-builder'),
            value: newDomain,
            onChange: (val) => setNewDomain(val),
            placeholder: 'example.com',
            __nextHasNoMarginBottom: true
          })
        ]),
        el('div', { style: { minWidth: '150px' } }, [
          el(SelectControl, {
            label: __('Type', 'vapt-builder'),
            value: isWildcardNew ? 'wildcard' : 'standard',
            options: [
              { label: __('Standard', 'vapt-builder'), value: 'standard' },
              { label: __('Wildcard (*.domain)', 'vapt-builder'), value: 'wildcard' }
            ],
            onChange: (val) => setIsWildcardNew(val === 'wildcard'),
            __nextHasNoMarginBottom: true
          })
        ]),
        el(Button, {
          isPrimary: true,
          onClick: () => {
            const domain = (newDomain || '').trim();
            if (!domain) return;
            // console.log('Adding domain:', domain, 'isWildcard:', isWildcardNew);
            addDomain(domain, isWildcardNew);
            setNewDomain('');
            setIsWildcardNew(false);
          },
          style: { alignSelf: 'flex-end', height: '32px' }
        }, __('Add Domain', 'vapt-builder')),
        (selectedDomains || []).length > 0 && el(Button, {
          isDestructive: true,
          onClick: () => {
            const count = (selectedDomains || []).length;
            setConfirmState({
              message: sprintf(__('Are you sure you want to delete %d selected domains?', 'vapt-builder'), count),
              onConfirm: () => {
                batchDeleteDomains(selectedDomains);
                setConfirmState(null);
              },
              isDestructive: true
            });
          },
          style: { alignSelf: 'flex-end', height: '32px', marginLeft: 'auto' }
        }, __('Delete Selected', 'vapt-builder'))
      ]),

      el('table', { key: 'table', className: 'wp-list-table widefat fixed striped' }, [
        el('thead', null, el('tr', null, [
          el('th', { style: { width: '40px' } }, el('div', { style: { display: 'flex', alignItems: 'center', gap: '4px' } }, [
            el(CheckboxControl, {
              checked: (domains || []).length > 0 && (selectedDomains || []).length === (domains || []).length,
              indeterminate: (selectedDomains || []).length > 0 && (selectedDomains || []).length < (domains || []).length,
              onChange: (val) => setSelectedDomains(val ? (domains || []).map(d => d.id) : []),
              __nextHasNoMarginBottom: true
            }),
            el('span', { style: { fontSize: '10px', opacity: 0.6, fontWeight: 600, whiteSpace: 'nowrap' } }, __('ALL', 'vapt-builder'))
          ])),
          el('th', {
            style: { cursor: 'pointer', userSelect: 'none' },
            onClick: () => requestSort('domain')
          }, [
            __('Domain', 'vapt-builder'),
            el(SortIndicator, { column: 'domain' })
          ]),
          el('th', { style: { width: '100px' } }, __('Status', 'vapt-builder')),
          el('th', {
            style: { width: '180px', cursor: 'pointer', userSelect: 'none' },
            onClick: () => requestSort('is_wildcard')
          }, [
            __('Type', 'vapt-builder'),
            el(SortIndicator, { column: 'is_wildcard' })
          ]),
          el('th', { style: { width: '120px' } }, __('License', 'vapt-builder')),
          el('th', null, __('Features Enabled', 'vapt-builder')),
          el('th', { style: { width: '120px' } }, __('Expiry Date', 'vapt-builder')),
          el('th', { style: { width: '220px' } }, __('Actions', 'vapt-builder'))
        ])),
        el('tbody', null, sortedDomains.map((d) => el('tr', { key: d.id }, [
          el('td', null, el(CheckboxControl, {
            checked: (selectedDomains || []).includes(d.id),
            onChange: () => toggleDomainSelection(d.id),
            __nextHasNoMarginBottom: true
          })),
          el('td', null, el('strong', null, d.domain)),
          el('td', null, el(Button, {
            isLink: true,
            onClick: () => {
              const currentEnabled = !(d.is_enabled === '0' || d.is_enabled === false || d.is_enabled === 0);
              addDomain(d.domain, (d.is_wildcard === '1' || d.is_wildcard === true || d.is_wildcard === 1), !currentEnabled, d.id);
            },
            style: { color: (d.is_enabled === '0' || d.is_enabled === false || d.is_enabled === 0) ? '#d63638' : '#00a32a', fontWeight: 600, textDecoration: 'none' },
            title: __('Click to toggle domain status', 'vapt-builder')
          }, [
            el(Dashicon, { icon: (d.is_enabled === '0' || d.is_enabled === false || d.is_enabled === 0) ? 'hidden' : 'visibility', size: 16, style: { marginRight: '4px' } }),
            (d.is_enabled === '0' || d.is_enabled === false || d.is_enabled === 0) ? __('Disabled', 'vapt-builder') : __('Active', 'vapt-builder')
          ])),
          el('td', null, el('div', { style: { display: 'flex', alignItems: 'center', gap: '8px' } }, [
            el(Button, {
              isLink: true,
              onClick: (e) => {
                e.preventDefault();
                const currentWildcard = (d.is_wildcard === '1' || d.is_wildcard === true || d.is_wildcard === 1);
                const nextWildcard = !currentWildcard;
                addDomain(d.domain, nextWildcard, !(d.is_enabled === '0' || d.is_enabled === false || d.is_enabled === 0), d.id);
              },
              style: { textDecoration: 'none', color: (d.is_wildcard === '1' || d.is_wildcard === true || d.is_wildcard === 1) ? '#2271b1' : '#64748b', fontWeight: 600 },
              title: __('Click to toggle domain type', 'vapt-builder')
            }, (d.is_wildcard === '1' || d.is_wildcard === true || d.is_wildcard === 1) ? __('Wildcard', 'vapt-builder') : __('Standard', 'vapt-builder')),
            el(Dashicon, { icon: 'update', size: 14, style: { opacity: 0.5 } })
          ])),
          el('td', null, el('span', {
            style: {
              display: 'inline-block',
              padding: '2px 8px',
              borderRadius: '4px',
              fontSize: '11px',
              fontWeight: 600,
              textTransform: 'capitalize',
              background: d.license_type === 'developer' ? '#f3e8ff' : (d.license_type === 'pro' ? '#fff1f2' : '#f1f5f9'),
              color: d.license_type === 'developer' ? '#6b21a8' : (d.license_type === 'pro' ? '#be123c' : '#475569'),
              border: '1px solid transparent'
            }
          }, d.license_type || 'Standard')),
          el('td', null, (Array.isArray(d.features) && d.features.length > 0) ? el(Button, {
            isLink: true,
            onClick: (e) => {
              e.preventDefault();
              setViewFeaturesModalDomain(d);
              setViewFeaturesModalOpen(true);
            }
          }, `${d.features.length} ${__('Features', 'vapt-builder')}`) : `${(Array.isArray(d.features) ? d.features.length : 0)} ${__('Features', 'vapt-builder')}`),
          el('td', null, el('span', { style: { fontSize: '12px', color: (d.license_type !== 'developer' && d.manual_expiry_date && new Date(d.manual_expiry_date) < new Date()) ? '#dc2626' : 'inherit' } },
            d.license_type === 'developer'
              ? __('Never', 'vapt-builder')
              : (d.manual_expiry_date ? new Date(d.manual_expiry_date).toLocaleDateString() : '-')
          )),
          el('td', null, el('div', { style: { display: 'flex', gap: '8px' } }, [
            el(Button, {
              isSecondary: true,
              isSmall: true,
              onClick: () => {
                setEditDomainData({
                  id: d.id,
                  domain: d.domain,
                  is_wildcard: (d.is_wildcard === '1' || d.is_wildcard === true || d.is_wildcard === 1),
                  is_enabled: !(d.is_enabled === '0' || d.is_enabled === false || d.is_enabled === 0)
                });
                setEditModalOpen(true);
              }
            }, __('Edit', 'vapt-builder')),
            el(Button, {
              isSecondary: true,
              isSmall: true,
              onClick: () => { setSelectedDomain(d); setDomainModalOpen(true); }
            }, __('Manage Features', 'vapt-builder')),
            el(Button, {
              isDestructive: true,
              isSmall: true,
              onClick: () => {
                setConfirmState({
                  message: sprintf(__('Are you sure you want to delete the domain "%s"? This action cannot be undone.', 'vapt-builder'), d.domain),
                  onConfirm: () => {
                    deleteDomain(d.id);
                    setConfirmState(null);
                  },
                  isDestructive: true
                });
              }
            }, __('Delete', 'vapt-builder'))
          ]))
        ])))
      ]),

      // Edit Domain Modal
      isEditModalOpen && el(Modal, {
        title: __('Edit Domain Settings', 'vapt-builder'),
        onRequestClose: () => setEditModalOpen(false),
        style: { maxWidth: '500px' }
      }, [
        el('div', { style: { padding: '10px 0' } }, [
          el(TextControl, {
            label: __('Domain Name', 'vapt-builder'),
            value: editDomainData.domain,
            onChange: (val) => setEditDomainData({ ...editDomainData, domain: val })
          }),
          el(SelectControl, {
            label: __('Type', 'vapt-builder'),
            value: editDomainData.is_wildcard ? 'wildcard' : 'standard',
            options: [
              { label: __('Standard', 'vapt-builder'), value: 'standard' },
              { label: __('Wildcard (*.domain)', 'vapt-builder'), value: 'wildcard' }
            ],
            onChange: (val) => setEditDomainData({ ...editDomainData, is_wildcard: val === 'wildcard' })
          }),
          el(ToggleControl, {
            label: __('Enabled', 'vapt-builder'),
            checked: editDomainData.is_enabled,
            onChange: (val) => setEditDomainData({ ...editDomainData, is_enabled: val }),
            help: __('Enable or disable all VAPT features for this domain.', 'vapt-builder')
          }),
          el('div', { style: { marginTop: '20px', display: 'flex', justifyContent: 'flex-end', gap: '10px' } }, [
            el(Button, { isSecondary: true, onClick: () => setEditModalOpen(false) }, __('Cancel', 'vapt-builder')),
            el(Button, {
              isPrimary: true,
              onClick: () => {
                addDomain(editDomainData.domain, editDomainData.is_wildcard, editDomainData.is_enabled, editDomainData.id);
                setEditModalOpen(false);
              }
            }, __('Update Domain', 'vapt-builder'))
          ])
        ])
      ]),
      isDomainModalOpen && selectedDomain && el(Modal, {
        key: 'modal',
        title: sprintf(__('Features for %s', 'vapt-builder'), selectedDomain.domain),
        onRequestClose: () => setDomainModalOpen(false),
        className: 'vapt-domain-features-modal',
        style: { maxWidth: '1400px', width: '90%' }
      }, [
        // Status Visibility Filters
        el('div', {
          style: {
            marginBottom: '20px',
            padding: '12px 20px',
            background: '#f8fafc',
            borderRadius: '8px',
            border: '1px solid #e2e8f0',
            display: 'flex',
            alignItems: 'center',
            gap: '20px'
          }
        }, [
          el('span', { style: { fontSize: '11px', fontWeight: 700, color: '#64748b', textTransform: 'uppercase' } }, __('Status Visibility:')),
          el(Button, {
            isPrimary: (statusFilters || []).length !== 4,
            variant: (statusFilters || []).length === 4 ? 'secondary' : 'primary',
            onClick: () => {
              if ((statusFilters || []).length === 4) setStatusFilters([]);
              else setStatusFilters(['draft', 'develop', 'test', 'release']);
            },
            style: {
              fontWeight: 700,
              padding: '8px 20px',
              height: 'auto',
              boxShadow: (statusFilters || []).length !== 4 ? '0 2px 4px rgba(34, 113, 177, 0.2)' : 'none'
            }
          }, (statusFilters || []).length === 4 ? __('Reset All Filters', 'vapt-builder') : __('Select All Statuses', 'vapt-builder')),
          el('div', { style: { display: 'flex', gap: '15px', paddingLeft: '20px', borderLeft: '2px solid #e2e8f0' } }, [
            { label: __('Draft', 'vapt-builder'), value: 'draft' },
            { label: __('Develop', 'vapt-builder'), value: 'develop' },
            { label: __('Test', 'vapt-builder'), value: 'test' },
            { label: __('Release', 'vapt-builder'), value: 'release' }
          ].filter(o => o.value).map(opt => el(CheckboxControl, {
            key: opt.value,
            label: opt.label,
            checked: statusFilters.includes(opt.value),
            onChange: (val) => {
              if (val) setStatusFilters([...statusFilters, opt.value]);
              else if ((statusFilters || []).length > 1) setStatusFilters(statusFilters.filter(v => v !== opt.value));
            },
            __nextHasNoMarginBottom: true
          })))
        ]),

        el('div', { style: { display: 'flex', gap: '0', height: '60vh', border: '1px solid #e2e8f0', borderRadius: '8px', overflow: 'hidden' } }, [
          // Left Sidebar: Categories
          el('aside', {
            style: {
              width: '240px',
              flexShrink: 0,
              background: '#fcfcfd',
              borderRight: '1px solid #e2e8f0',
              padding: '20px 0',
              overflowY: 'auto'
            }
          }, [
            el('div', { style: { padding: '0 20px 10px', fontSize: '11px', fontWeight: 700, color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.05em' } }, __('Feature Categories')),
            el('div', { id: 'vapt-domain-features-sidebar-categories', style: { display: 'flex', flexDirection: 'column' } }, [
              // All Categories Link
              el('a', {
                id: 'vapt-category-link-all',
                href: '#',
                onClick: (e) => { e.preventDefault(); setActiveCategory('all'); },
                className: 'vapt-sidebar-link' + (activeCategory === 'all' ? ' is-active' : ''),
                style: {
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  padding: '10px 20px',
                  textDecoration: 'none',
                  color: activeCategory === 'all' ? '#2271b1' : '#64748b',
                  background: activeCategory === 'all' ? '#eff6ff' : 'transparent',
                  fontWeight: activeCategory === 'all' ? 600 : 500,
                  fontSize: '13px',
                  borderRight: activeCategory === 'all' ? '3px solid #2271b1' : 'none'
                }
              }, [
                el('span', null, __('All Categories', 'vapt-builder')),
                el('span', { style: { fontSize: '10px', padding: '2px 6px', borderRadius: '10px', background: activeCategory === 'all' ? '#dbeafe' : '#f1f5f9' } }, (Array.isArray(filteredByStatus) ? filteredByStatus : []).length)
              ]),
              // Category Links
              ...categories.map(cat => {
                const count = (Array.isArray(filteredByStatus) ? filteredByStatus : []).filter(f => (f.category || 'Uncategorized') === cat).length;
                const isActive = activeCategory === cat;
                return el('a', {
                  key: cat,
                  href: '#',
                  onClick: (e) => { e.preventDefault(); setActiveCategory(cat); },
                  className: 'vapt-sidebar-link' + (isActive ? ' is-active' : ''),
                  style: {
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    padding: '10px 20px',
                    textDecoration: 'none',
                    color: isActive ? '#2271b1' : '#64748b',
                    background: isActive ? '#eff6ff' : 'transparent',
                    fontWeight: isActive ? 600 : 500,
                    fontSize: '13px',
                    borderRight: isActive ? '3px solid #2271b1' : 'none',
                    whiteSpace: 'nowrap',
                    overflow: 'visible'
                  }
                }, [
                  el('span', { style: { overflow: 'hidden', textOverflow: 'ellipsis' } }, cat),
                  el('span', { style: { fontSize: '10px', padding: '2px 6px', borderRadius: '10px', background: isActive ? '#dbeafe' : '#f1f5f9', marginLeft: '8px', flexShrink: 0 } }, count)
                ]);
              })
            ])
          ]),

          // Main Content: Feature Cards
          el('div', {
            style: {
              flexGrow: 1,
              padding: '25px',
              background: '#fff',
              overflowY: 'auto'
            }
          }, [
            ((Array.isArray(displayFeatures) ? displayFeatures : []).length === 0) ? el('div', { style: { textAlign: 'center', padding: '40px', color: '#94a3b8' } }, __('No features matching the current selection.', 'vapt-builder')) :
              Object.entries(featuresByCategory).map(([catName, catFeatures]) => el(Fragment, { key: catName }, [
                el('h3', { className: 'vapt-category-header' }, [
                  el(Dashicon, { icon: 'category', size: 16 }),
                  catName
                ]),
                el('div', { className: 'vapt-feature-grid' }, catFeatures.map(f => el('div', {
                  key: f.key,
                  className: `vapt-domain-feature-card ${f.exists_in_multiple_files ? 'vapt-feature-multi-file' : (f.is_from_active_file === false ? 'vapt-feature-inactive-only' : '')}`,
                  style: {
                    padding: '20px',
                    border: '1px solid #e2e8f0',
                    borderRadius: '12px',
                    background: '#fff',
                    display: 'flex',
                    flexDirection: 'column',
                    transition: 'all 0.3s',
                    boxShadow: '0 1px 2px rgba(0,0,0,0.05)'
                  }
                }, [
                  el('div', { style: { marginBottom: '20px' } }, [
                    el('div', { style: { display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '8px' } }, [
                      el('h4', { style: { margin: 0, fontSize: '16px', fontWeight: 700, color: '#1e293b' } }, f.label),
                      el('span', {
                        className: `vapt-status-pill status-${(f.status || '').toLowerCase()}`,
                        style: {
                          fontSize: '9px',
                          fontWeight: 700,
                          textTransform: 'uppercase',
                          padding: '2px 8px',
                          borderRadius: '4px',
                          color: '#fff',
                          background: (f.status === 'Develop' || f.status === 'develop') ? '#10b981' :
                            (f.status === 'Test' || f.status === 'test') ? '#eab308' :
                              (f.status === 'Release' || f.status === 'release' || f.status === 'implemented') ? '#f97316' : '#94a3b8',
                          border: 'none',
                          boxShadow: '0 1px 2px rgba(0,0,0,0.1)'
                        }
                      }, f.status)
                    ]),
                    el('p', { style: { margin: 0, fontSize: '13px', color: '#64748b', lineHeight: '1.5' } }, f.description)
                  ]),
                  el('div', {
                    id: `vapt-domain-feature-footer-${f.key}`,
                    style: {
                      marginTop: 'auto',
                      paddingTop: '15px',
                      borderTop: '1px solid #f1f5f9',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between'
                    }
                  }, [
                    el('span', { id: `vapt-domain-feature-status-text-${f.key}`, style: { fontSize: '12px', fontWeight: 600, color: '#475569' } }, (Array.isArray(selectedDomain.features) ? selectedDomain.features : []).includes(f.key) ? __('Active', 'vapt-builder') : __('Disabled', 'vapt-builder')),
                    el(ToggleControl, {
                      checked: (Array.isArray(selectedDomain.features) ? selectedDomain.features : []).includes(f.key),
                      onChange: (val) => {
                        const newFeats = val
                          ? [...(Array.isArray(selectedDomain.features) ? selectedDomain.features : []), f.key]
                          : (Array.isArray(selectedDomain.features) ? selectedDomain.features : []).filter(k => k !== f.key);
                        updateDomainFeatures(selectedDomain.id, newFeats);
                        setSelectedDomain({ ...selectedDomain, features: newFeats });
                      },
                      __nextHasNoMarginBottom: true,
                      style: { margin: 0 }
                    })
                  ])
                ])))
              ]))
          ])
        ]),
        el('div', { style: { marginTop: '20px', textAlign: 'right' } }, el(Button, {
          isPrimary: true,
          onClick: () => setDomainModalOpen(false)
        }, __('Done', 'vapt-builder')))
      ]),
      // View Features Modal
      viewFeaturesModalOpen && viewFeaturesModalDomain && el(Modal, {
        id: 'vapt-view-features-modal',
        title: sprintf(__('Enabled Features for %s', 'vapt-builder'), viewFeaturesModalDomain.domain),
        onRequestClose: () => setViewFeaturesModalOpen(false),
        style: { maxWidth: '1200px', width: '90%' }
      }, [
        el('div', {
          id: 'vapt-view-features-grid-wrap',
          style: {
            display: 'grid',
            gridTemplateColumns: 'repeat(3, 1fr)',
            gap: '20px',
            padding: '20px',
            maxHeight: '70vh',
            overflowY: 'auto'
          }
        },
          (features || []).filter(f => (Array.isArray(viewFeaturesModalDomain.features) ? viewFeaturesModalDomain.features : []).includes(f.key)).map(f =>
            el(Card, {
              key: f.key,
              style: { border: '1px solid #e2e8f0', borderRadius: '8px', boxShadow: 'sm' }
            }, [
              el(CardHeader, {
                style: {
                  background: '#f8fafc',
                  borderBottom: '1px solid #e2e8f0',
                  padding: '12px 16px',
                  display: 'flex',
                  flexDirection: 'column',
                  alignItems: 'flex-start',
                  gap: '5px'
                }
              }, [
                el('span', {
                  style: {
                    fontSize: '9px',
                    fontWeight: 600,
                    textTransform: 'uppercase',
                    padding: '2px 6px',
                    borderRadius: '4px',
                    background: '#e2e8f0',
                    color: '#475569'
                  }
                }, f.category || 'General'),
                el('strong', { style: { fontSize: '13px', color: '#1e293b' } }, f.label)
              ]),
              el(CardBody, { style: { padding: '16px' } }, [
                el('div', { style: { marginBottom: '10px' } }, [
                  el('span', {
                    style: {
                      display: 'inline-block',
                      fontSize: '10px',
                      fontWeight: 700,
                      textTransform: 'uppercase',
                      padding: '3px 8px',
                      borderRadius: '12px',
                      color: '#fff',
                      background: (f.status === 'Develop' || f.status === 'develop') ? '#10b981' :
                        (f.status === 'Test' || f.status === 'test') ? '#eab308' :
                          (f.status === 'Release' || f.status === 'release' || f.status === 'implemented') ? '#f97316' : '#94a3b8',
                      boxShadow: '0 1px 2px rgba(0,0,0,0.1)'
                    }
                  }, f.status || 'Unknown')
                ]),
                el('p', { style: { fontSize: '12px', color: '#64748b', margin: 0, lineHeight: '1.5' } }, f.description)
              ])
            ])
          )
        ),
        el('div', { style: { marginTop: '20px', textAlign: 'right', borderTop: '1px solid #e2e8f0', paddingTop: '15px' } },
          el(Button, { isPrimary: true, onClick: () => setViewFeaturesModalOpen(false) }, __('Close', 'vapt-builder'))
        )
      ])
    ]);
  };

  const BuildGenerator = ({ domains, features, activeFile, setAlertState }) => {
    const [buildDomain, setBuildDomain] = useState('');
    const [buildVersion, setBuildVersion] = useState(settings.pluginVersion || '3.5.1');
    const [includeConfig, setIncludeConfig] = useState(true);
    const [includeData, setIncludeData] = useState(false);
    const [whiteLabel, setWhiteLabel] = useState({
      name: 'VAPT Security',
      description: '',
      author: 'Tanveer Malik',
      plugin_uri: 'https://vapt.builder',
      author_uri: 'https://tanveermalik.com',
      text_domain: 'vapt-security'
    });
    const [generating, setGenerating] = useState(false);
    const [downloadUrl, setDownloadUrl] = useState(null);
    const [importedAt, setImportedAt] = useState(null);
    const [licenseScope, setLicenseScope] = useState('single');
    const [installationLimit, setInstallationLimit] = useState(1);

    // Auto-Generation Effect
    useEffect(() => {
      const slug = whiteLabel.name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');

      // Calculate enabled features
      const selectedDomain = (Array.isArray(domains) ? domains : []).find(d => d.domain === buildDomain);
      const feats = selectedDomain ? (Array.isArray(selectedDomain.features) ? selectedDomain.features : []) : [];
      const featCount = feats.length;

      const desc = `${whiteLabel.name} Build for ${buildDomain || 'Universal Scope'} is a specialized security hardening package providing comprehensive defense against OWASP Top 10 vulnerabilities. ` +
        `This build integrates ${featCount} active security modules tailored for WordPress environments. ` +
        `Requires PHP 7.4 or higher and WordPress 5.8+; optimized for Apache/htaccess enforcement. ` +
        `Generated by VAPT Builder.`;

      setWhiteLabel(prev => ({
        ...prev,
        text_domain: slug,
        description: desc
      }));

      // Sync Imported At
      if (selectedDomain && selectedDomain.imported_at) {
        setImportedAt(selectedDomain.imported_at);
      } else {
        setImportedAt(null);
      }
    }, [whiteLabel.name, buildDomain, domains]);

    const runBuild = (type = 'full_build') => {
      if (!buildDomain && type !== 'config_only') {
        setAlertState({ message: __('Please select a target domain.', 'vapt-builder'), type: 'error' });
        return;
      }
      setGenerating(true);
      setDownloadUrl(null);
      const selectedDomain = (Array.isArray(domains) ? domains : []).find(d => d.domain === buildDomain);
      const buildFeatures = selectedDomain ? (Array.isArray(selectedDomain.features) ? selectedDomain.features : []) : (Array.isArray(features) ? features : []).filter(f => f.status === 'implemented').map(f => f.key);

      apiFetch({
        path: 'vapt/v1/build/generate',
        method: 'POST',
        data: {
          domain: buildDomain.trim(),
          version: buildVersion.trim(),
          features: buildFeatures,
          generate_type: type,
          include_config: includeConfig,
          include_data: includeData,
          license_scope: licenseScope,
          installation_limit: installationLimit,
          white_label: {
            name: whiteLabel.name.trim(),
            description: whiteLabel.description.trim(),
            author: whiteLabel.author.trim(),
            plugin_uri: whiteLabel.plugin_uri.trim(),
            author_uri: whiteLabel.author_uri.trim(),
            text_domain: whiteLabel.text_domain.trim()
          }
        }
      }).then((res) => {
        if (res && res.download_url) {
          window.location.href = res.download_url;
          setAlertState({ message: __('Build generated and downloading!', 'vapt-builder'), type: 'success' });
        } else {
          setAlertState({ message: __('Build failed: No download URL received.', 'vapt-builder'), type: 'error' });
        }
        setGenerating(false);
      }).catch((error) => {
        setGenerating(false);
        setAlertState({ message: __('Build failed! ' + (error.message || ''), 'vapt-builder'), type: 'error' });
      });
    };

    const saveToServer = () => {
      if (!buildDomain) {
        setAlertState({ message: __('Please select a target domain.', 'vapt-builder'), type: 'error' });
        return;
      }
      setGenerating(true);
      const selectedDomain = (Array.isArray(domains) ? domains : []).find(d => d.domain === buildDomain);
      const buildFeatures = selectedDomain ? (Array.isArray(selectedDomain.features) ? selectedDomain.features : []) : [];

      apiFetch({
        path: 'vapt/v1/build/save-config',
        method: 'POST',
        data: {
          domain: buildDomain.trim(),
          version: buildVersion.trim(),
          features: buildFeatures,
          license_scope: licenseScope,
          installation_limit: installationLimit
        }
      }).then(res => {
        if (res.success) {
          setAlertState({ message: __('Config saved to server successfully!', 'vapt-builder'), type: 'success' });
        } else {
          setAlertState({ message: __('Failed to save config.', 'vapt-builder'), type: 'error' });
        }
        setGenerating(false);
      }).catch(err => {
        setGenerating(false);
        setAlertState({ message: 'Save failed: ' + err.message, type: 'error' });
      });
    };

    const forceReImport = () => {
      if (!buildDomain) return;
      setGenerating(true);
      apiFetch({
        path: 'vapt/v1/build/sync-config',
        method: 'POST',
        data: { domain: buildDomain }
      }).then(res => {
        if (res.success) {
          setImportedAt(res.imported_at);
          setAlertState({ message: `Config Re-Imported! Found ${res.features_count} features.`, type: 'success' });
        } else {
          setAlertState({ message: 'Import Failed: ' + (res.error || 'Unknown'), type: 'warning' });
        }
        setGenerating(false);
      }).catch(err => {
        setGenerating(false);
        setAlertState({ message: 'Import Error: ' + err.message, type: 'error' });
      });
    }

    // Helper for Horizontal Labels
    const FieldRow = ({ label, children }) => el('div', { style: { display: 'flex', alignItems: 'center', marginBottom: '8px' } }, [
      el('label', { style: { width: '85px', fontSize: '12px', fontWeight: '500', color: '#64748b', flexShrink: 0 } }, label),
      el('div', { style: { flex: 1 } }, children)
    ]);

    return el('div', { className: 'vapt-build-generator' }, [
      el('div', { style: { display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '25px', marginTop: '30px' } }, [
        el(Icon, { icon: 'hammer', size: 24 }),
        el('h2', { style: { margin: 0, fontSize: '20px' } }, __('Generate New Build', 'vapt-builder'))
      ]),
      // 60/40 Layout
      el('div', { style: { display: 'grid', gridTemplateColumns: '1.6fr 1fr', gap: '25px', alignItems: 'start' } }, [

        // LEFT COLUMN: Configuration
        el(Card, { style: { display: 'flex', flexDirection: 'column', borderRadius: '8px', border: '1px solid #e2e8f0', height: '100%' } }, [
          el(CardHeader, { style: { background: '#f8fafc', borderBottom: '1px solid #e2e8f0', padding: '12px 20px' } }, [
            el('h3', { style: { margin: 0, fontSize: '15px', display: 'flex', alignItems: 'center', gap: '8px' } }, [
              el(Icon, { icon: 'admin-settings', size: 16 }),
              __('Configuration Details', 'vapt-builder')
            ])
          ]),
          el(CardBody, { style: { padding: '20px', display: 'flex', flexDirection: 'column', gap: '15px', flex: 1 } }, [
            // Domain & Config Toggle (Side-by-Side)
            el('div', { style: { display: 'flex', alignItems: 'center', gap: '20px', marginBottom: '10px' } }, [
              el('div', { style: { flex: 1, display: 'flex', alignItems: 'center' } }, [
                el('label', { style: { width: '85px', fontSize: '12px', fontWeight: '500', color: '#64748b', flexShrink: 0 } }, __('Target Domain', 'vapt-builder')),
                el('div', { style: { flex: 1 } },
                  el(SelectControl, {
                    value: buildDomain,
                    options: [
                      { label: __('--- Select Target Domain ---', 'vapt-builder'), value: '' },
                      ...(Array.isArray(domains) ? domains : []).filter(d => d.status !== 'inactive').map(d => ({ label: d.domain, value: d.domain }))
                    ],
                    onChange: (val) => setBuildDomain(val),
                    style: { marginBottom: 0 }
                  })
                )
              ]),
              el('div', { style: { display: 'flex', alignItems: 'center', gap: '5px' } }, [
                el(ToggleControl, {
                  label: __('Include Config', 'vapt-builder'),
                  checked: includeConfig,
                  onChange: (val) => setIncludeConfig(val),
                  help: null,
                  style: { marginBottom: 0 }
                }),
                el(Tooltip, { text: __('Include current feature configurations & security rules.', 'vapt-builder') },
                  el('span', { className: 'dashicons dashicons-editor-help', style: { fontSize: '14px', color: '#94a3b8', cursor: 'help', marginTop: '-4px' } })
                )
              ]),
              el('div', { style: { display: 'flex', alignItems: 'center', gap: '5px' } }, [
                el(ToggleControl, {
                  label: __('Include Active Data', 'vapt-builder'),
                  checked: includeData,
                  onChange: (val) => setIncludeData(val),
                  help: null,
                  style: { marginBottom: 0 }
                }),
                el(Tooltip, { text: sprintf(__('Include Risk Catalog and definitions from active file: %s (Found %d items).', 'vapt-builder'), activeFile || 'Default', features ? features.length : 0) },
                  el('span', { className: 'dashicons dashicons-editor-help', style: { fontSize: '14px', color: '#94a3b8', cursor: 'help', marginTop: '-4px' } })
                )
              ])
            ]),

            // Horizontal Fields in 2-Col Grid
            el('div', { style: { display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '40px', background: '#eef2f6', padding: '15px', borderRadius: '6px', border: '1px solid #e2e8f0' } }, [
              // Col 1
              el('div', null, [
                el(FieldRow, { label: __('Plugin Name', 'vapt-builder') },
                  el(TextControl, { value: whiteLabel.name, onChange: (val) => setWhiteLabel({ ...whiteLabel, name: val }), style: { marginBottom: 0 } })
                ),
                el(FieldRow, { label: __('Author', 'vapt-builder') },
                  el(TextControl, { value: whiteLabel.author, onChange: (val) => setWhiteLabel({ ...whiteLabel, author: val }), style: { marginBottom: 0 } })
                ),
                el(FieldRow, { label: __('Text Domain', 'vapt-builder') },
                  el(TextControl, { value: whiteLabel.text_domain, readOnly: true, style: { marginBottom: 0, background: '#f8fafc' } })
                ),
              ]),
              // Col 2
              el('div', null, [
                el(FieldRow, { label: __('Plugin URI', 'vapt-builder') },
                  el(TextControl, { value: whiteLabel.plugin_uri, onChange: (val) => setWhiteLabel({ ...whiteLabel, plugin_uri: val }), style: { marginBottom: 0 } })
                ),
                el(FieldRow, { label: __('Author URI', 'vapt-builder') },
                  el(TextControl, { value: whiteLabel.author_uri, onChange: (val) => setWhiteLabel({ ...whiteLabel, author_uri: val }), style: { marginBottom: 0 } })
                ),
                el(FieldRow, { label: __('Version', 'vapt-builder') },
                  el(TextControl, { value: buildVersion, onChange: (val) => setBuildVersion(val), style: { marginBottom: 0 } })
                ),
              ]),
              // Col 3 (License Scope)
              el('div', null, [
                el(FieldRow, { label: __('License Scope', 'vapt-builder') },
                  el(SelectControl, {
                    value: licenseScope,
                    options: [
                      { label: __('Single Domain', 'vapt-builder'), value: 'single' },
                      { label: __('Multi-Site', 'vapt-builder'), value: 'multisite' }
                    ],
                    onChange: (val) => setLicenseScope(val),
                    style: { marginBottom: 0 }
                  })
                ),
              ]),
              // Col 4 (Inst. Limit - appear next to License Scope)
              el('div', null, [
                licenseScope === 'multisite' && el(FieldRow, { label: __('Inst. Limit', 'vapt-builder') },
                  el(TextControl, {
                    type: 'number',
                    value: installationLimit,
                    min: 1,
                    onChange: (val) => setInstallationLimit(parseInt(val) || 1),
                    style: { marginBottom: 0 }
                  })
                )
              ])
            ]),

            el('div', { style: { marginTop: '5px' } }, [
              el('label', { style: { display: 'block', fontSize: '12px', fontWeight: '500', color: '#64748b', marginBottom: '8px' } }, __('Plugin Description', 'vapt-builder')),
              el(TextareaControl, {
                value: whiteLabel.description,
                rows: 3,
                onChange: (val) => setWhiteLabel({ ...whiteLabel, description: val }),
                style: { marginBottom: '0', fontSize: '13px', lineHeight: '1.5' }
              })
            ]),

            el('div', { style: { display: 'flex', gap: '10px', marginTop: 'auto', paddingTop: '15px', borderTop: '1px solid #eee' } }, [
              el(Button, {
                isSecondary: true,
                style: { flex: 1, justifyContent: 'center' },
                onClick: saveToServer,
                disabled: generating || !buildDomain
              }, [
                el(Icon, { icon: 'upload', size: 18, style: { marginRight: '5px' } }),
                __('Save to Server', 'vapt-builder')
              ]),
              el(Button, {
                isPrimary: true,
                style: { flex: 1, justifyContent: 'center', background: '#357abd' },
                onClick: () => runBuild('full_build'),
                disabled: generating || !buildDomain
              }, [
                el(Icon, { icon: 'download', size: 18, style: { marginRight: '5px' } }),
                generating ? __('Generating...', 'vapt-Copilot') : __('Download Build', 'vapt-Copilot')
              ])
            ])
          ])
        ]),

        // RIGHT COLUMN: Status (Equal Height)
        el(Card, { style: { borderRadius: '8px', border: '1px solid #e2e8f0', height: '100%', background: '#fff' } }, [
          // Content updated with better styling in next tool call or implicit here?
          // Using existing structure but ensuring it matches visual requirements
          el(CardHeader, { style: { background: '#f8fafc', borderBottom: '1px solid #e2e8f0', padding: '12px 20px' } }, [
            el('h4', { style: { margin: 0, fontSize: '14px', display: 'flex', alignItems: 'center', gap: '8px' } }, [
              el(Icon, { icon: 'info-outline', size: 16 }),
              __('Build Status & History', 'vapt-builder')
            ])
          ]),
          el(CardBody, { style: { padding: '20px' } }, [
            // ... Content Logic
            el('div', { style: { fontSize: '13px', color: '#64748b', lineHeight: '1.8' } }, [
              el('div', { style: { marginBottom: '10px', paddingBottom: '10px', borderBottom: '1px solid #eee', display: 'flex', justifyContent: 'space-between' } }, [
                el('strong', null, __('Generated Version', 'vapt-builder')),
                el('span', { style: { fontFamily: 'monospace', background: '#f1f5f9', padding: '2px 6px', borderRadius: '4px' } }, buildVersion)
              ]),
              el('div', { style: { marginBottom: '10px', paddingBottom: '10px', borderBottom: '1px solid #eee', display: 'flex', justifyContent: 'space-between' } }, [
                el('strong', null, __('Target Domain', 'vapt-builder')),
                el('code', { style: { color: '#0f172a' } }, buildDomain || 'None')
              ]),
              el('div', { style: { marginBottom: '10px', paddingBottom: '10px', borderBottom: '1px solid #eee', display: 'flex', justifyContent: 'space-between' } }, [
                el('strong', null, __('Active Features', 'vapt-builder')),
                el('span', { style: { fontWeight: '600', color: '#16a34a' } }, (() => {
                  const selectedDomain = domains.find(d => d.domain === buildDomain);
                  return selectedDomain ? (selectedDomain.features?.length || 0) : 0;
                })() + ' Modules')
              ]),
              el('div', { style: { display: 'flex', justifyContent: 'space-between', alignItems: 'center' } }, [
                el('strong', null, __('Last Import', 'vapt-builder')),
                el('span', { style: { fontSize: '11px', fontStyle: 'italic' } }, importedAt || 'Never')
              ])
            ]),
            el(Button, {
              isSecondary: true,
              style: { width: '100%', marginTop: '20px' },
              onClick: forceReImport,
              disabled: generating || !buildDomain
            }, __('Force Re-import from Server', 'vapt-builder')),
            el('p', { style: { fontSize: '11px', color: '#94a3b8', marginTop: '10px', textAlign: 'center' } }, __('Forces sync with vapt-locked-config.php', 'vapt-builder'))
          ])
        ])
      ])
    ]);
  };

  const LicenseManager = ({ domains, fetchData, isSuper, loading }) => {
    // Manage state for the selected domain (if multiple, allows switching)
    const [selectedDomainId, setSelectedDomainId] = useState(() => (Array.isArray(domains) && domains.length > 0) ? domains[0].id : null);

    // Derived current domain object
    const currentDomain = useMemo(() => {
      const doms = Array.isArray(domains) ? domains : [];
      // Use loose equality to handle string/number ID mismatches
      const found = doms.find(d => d.id == selectedDomainId);
      // console.log('LicenseManager Selection Debug:', { selectedDomainId, found, allDomains: doms });
      return found || (doms.length > 0 ? doms[0] : null);
    }, [domains, selectedDomainId]);

    // Local Form State
    const [formState, setFormState] = useState({
      license_type: 'standard',
      manual_expiry_date: '',
      auto_renew: false,
      license_scope: 'single',
      installation_limit: 1
    });

    // Sorting and Filtering state for the table
    const [sortBy, setSortBy] = useState('domain');
    const [sortOrder, setSortOrder] = useState('asc');
    const [searchQuery, setSearchQuery] = useState('');

    const sortedDomains = useMemo(() => {
      let doms = Array.isArray(domains) ? [...domains] : [];

      // Application of search filter
      if (searchQuery) {
        const query = searchQuery.toLowerCase();
        doms = doms.filter(d =>
          (d.domain || '').toLowerCase().includes(query) ||
          (d.license_id || '').toLowerCase().includes(query)
        );
      }

      // Sorting logic
      doms.sort((a, b) => {
        let valA = a[sortBy] || '';
        let valB = b[sortBy] || '';

        // Handle date sorting
        if (sortBy === 'first_activated_at' || sortBy === 'manual_expiry_date') {
          valA = valA ? new Date(valA).getTime() : 0;
          valB = valB ? new Date(valB).getTime() : 0;
        }

        if (typeof valA === 'string') {
          valA = valA.toLowerCase();
          valB = valB.toLowerCase();
        }

        if (valA < valB) return sortOrder === 'asc' ? -1 : 1;
        if (valA > valB) return sortOrder === 'asc' ? 1 : -1;
        return 0;
      });
      return doms;
    }, [domains, sortBy, sortOrder, searchQuery]);

    const [isSaving, setIsSaving] = useState(false);
    const [localStatus, setLocalStatus] = useState(null);
    const [confirmState, setConfirmState] = useState({ isOpen: false, type: null });

    // Sync form with current domain when selection changes or domain updates
    useEffect(() => {
      if (currentDomain && !isSaving && !loading) {
        const newType = currentDomain.license_type || 'standard';
        const newExpiry = currentDomain.manual_expiry_date ? currentDomain.manual_expiry_date.split(' ')[0] : '';
        const newAuto = !!parseInt(currentDomain.auto_renew);

        const newScope = currentDomain.license_scope || 'single';
        const newLimit = parseInt(currentDomain.installation_limit) || 1;

        // Only update if actually different to prevent flickering
        if (formState.license_type !== newType ||
          formState.manual_expiry_date !== newExpiry ||
          formState.auto_renew !== newAuto ||
          formState.license_scope !== newScope ||
          formState.installation_limit !== newLimit) {
          setFormState({
            license_type: newType,
            manual_expiry_date: newExpiry,
            auto_renew: newAuto,
            license_scope: newScope,
            installation_limit: newLimit
          });
        }
      }
    }, [currentDomain, isSaving, loading]);

    const isDirty = currentDomain ? (
      formState.license_type !== (currentDomain.license_type || 'standard') ||
      formState.manual_expiry_date !== (currentDomain.manual_expiry_date ? currentDomain.manual_expiry_date.split(' ')[0] : '') ||
      formState.auto_renew !== !!parseInt(currentDomain.auto_renew) ||
      formState.license_scope !== (currentDomain.license_scope || 'single') ||
      formState.installation_limit !== (parseInt(currentDomain.installation_limit) || 1)
    ) : false;

    if (!currentDomain) {
      return el(PanelBody, { title: __('License & Subscription Management', 'vapt-builder'), initialOpen: true },
        el('div', { style: { padding: '30px', textAlign: 'center' } }, [
          el('div', { style: { marginBottom: '20px', color: '#666' } }, __('No domains configured.', 'vapt-builder')),

          // Auto-Provision for Superadmins/Admins
          el('div', {
            style: {
              padding: '20px',
              background: '#f0f6fc',
              border: '1px solid #cce5ff',
              borderRadius: '8px',
              maxWidth: '500px',
              margin: '0 auto'
            }
          }, [
            el('h3', { style: { marginTop: 0 } }, __('Initialize Workspace License', 'vapt-builder')),
            el('p', null, sprintf(__('Detected environment: %s', 'vapt-builder'), window.location.hostname)),
            el('p', { style: { fontSize: '12px', color: '#666' } }, __('As a Superadmin, you can instantly provision a Developer License for this domain.', 'vapt-builder')),

            el(Button, {
              isPrimary: true,
              isBusy: isSaving,
              onClick: () => {
                setIsSaving(true);
                const hostname = window.location.hostname;
                // Calculate 100 years from now for Developer
                const tomorrow = new Date();
                tomorrow.setDate(tomorrow.getDate() + 36500);
                const expiry = tomorrow.toISOString().split('T')[0];

                apiFetch({
                  path: 'vapt/v1/domains/update',
                  method: 'POST',
                  data: {
                    domain: hostname,
                    license_type: 'developer',
                    auto_renew: 1,
                    manual_expiry_date: expiry,
                    license_id: 'DEV-' + Math.random().toString(36).substr(2, 9).toUpperCase()
                  }
                }).then(() => {
                  setLocalStatus({ message: 'Domain Provisioned!', type: 'success' });
                  fetchData(); // Will trigger re-render with new domain
                }).catch(err => {
                  setIsSaving(false);
                  setLocalStatus({ message: 'Provision Failed: ' + err.message, type: 'error' });
                });
              }
            }, sprintf(__('Provision %s (Developer)', 'vapt-builder'), window.location.hostname)),

            localStatus && el('p', { style: { color: localStatus.type === 'error' ? 'red' : 'green', marginTop: '10px' } }, localStatus.message)
          ])
        ])
      );
    }

    const handleUpdate = (isManualRenew = false) => {
      setIsSaving(true);
      setLocalStatus({
        message: isManualRenew ? __('Performing Manual Renewal...', 'vapt-builder') : __('Updating License...', 'vapt-builder'),
        type: 'info'
      });

      let payload = {
        id: currentDomain.id,
        license_type: formState.license_type,
        manual_expiry_date: formState.manual_expiry_date,
        auto_renew: formState.auto_renew ? 1 : 0,
        license_scope: formState.license_scope,
        installation_limit: formState.installation_limit,
        action: isManualRenew ? 'manual_renew' : 'update'
      };

      // Manual Renew Logic
      if (isManualRenew) {
        const baseDateStr = currentDomain.manual_expiry_date || new Date().toISOString().split('T')[0];
        const parts = baseDateStr.split(' ')[0].split('-');
        // Create date in local time at 00:00:00 using parts
        const baseDate = new Date(parts[0], parts[1] - 1, parts[2]);

        let durationDays = 30;
        if (formState.license_type === 'pro') durationDays = 365;
        if (formState.license_type === 'developer') durationDays = 36500; // ~100 years

        baseDate.setDate(baseDate.getDate() + durationDays);

        // Format back to YYYY-MM-DD manually to avoid UTC shift
        const y = baseDate.getFullYear();
        const m = String(baseDate.getMonth() + 1).padStart(2, '0');
        const d = String(baseDate.getDate()).padStart(2, '0');
        payload.manual_expiry_date = `${y}-${m}-${d}`;
        payload.renew_source = 'manual'; // Explicitly tag as manual
      }

      apiFetch({
        path: 'vapt/v1/domains/update',
        method: 'POST',
        data: payload
      }).then(res => {
        if (res.success && res.domain) {
          setLocalStatus({ message: __('License Updated!', 'vapt-builder'), type: 'success' });
          return fetchData(); // Return promise to chain
        }
      }).catch(err => {
        setLocalStatus({ message: __('Update Failed', 'vapt-builder'), type: 'error' });
      }).finally(() => {
        setIsSaving(false);
        setTimeout(() => setLocalStatus(null), 3000);
      });
    };

    const handleRollback = (type) => {
      setConfirmState({ isOpen: true, type });
    };

    const executeRollback = () => {
      const type = confirmState.type;
      setConfirmState({ isOpen: false, type: null });

      setIsSaving(true);
      setLocalStatus({ message: __('Reverting Renewals...', 'vapt-builder'), type: 'info' });

      apiFetch({
        path: 'vapt/v1/domains/update',
        method: 'POST',
        data: {
          domain: currentDomain.domain,
          action: type
        }
      }).then(res => {
        if (res.success && res.domain) {
          setLocalStatus({ message: __('Rollback Successful!', 'vapt-builder'), type: 'success' });
          return fetchData();
        }
      }).catch(err => {
        setLocalStatus({ message: __('Rollback Failed', 'vapt-builder'), type: 'error' });
      }).finally(() => {
        setIsSaving(false);
        setTimeout(() => setLocalStatus(null), 3000);
      });
    };

    // Helper to format date
    const formatDate = (dateStr) => {
      if (!dateStr || dateStr.startsWith('0000')) return __('Never / Invalid', 'vapt-builder');
      try {
        return new Date(dateStr).toLocaleDateString(undefined, { year: 'numeric', month: 'long', day: 'numeric' });
      } catch (e) {
        return dateStr;
      }
    };

    const toggleSort = (key) => {
      if (sortBy === key) {
        setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
      } else {
        setSortBy(key);
        setSortOrder('asc');
      }
    };

    const handleEdit = (domain) => {
      setSelectedDomainId(domain.id);
      window.scrollTo({ top: 0, behavior: 'smooth' });
    };

    return el(PanelBody, { title: __('License & Subscription Management', 'vapt-builder'), initialOpen: true }, [
      // TOP: Two-Column Form Grid
      el('div', { className: 'vapt-license-grid' }, [
        // LEFT: Status Card
        el('div', { className: 'vapt-license-card' }, [
          el('div', { className: 'vapt-card-header-row', style: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '15px' } }, [
            el('h3', { style: { margin: 0 } }, __('License Status', 'vapt-builder')),
            el('span', { className: `vapt-license-badge ${currentDomain.license_type || 'standard'}` },
              (currentDomain.license_type || 'Standard').toUpperCase()
            )
          ]),

          el('div', { className: 'vapt-info-row', style: { marginBottom: '15px' } }, [
            el(TextControl, {
              label: __('Domain Name', 'vapt-builder'),
              value: currentDomain.domain,
              readOnly: true,
              style: { background: '#f8fafc', color: '#64748b' }
            })
          ]),

          el('div', { style: { display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '15px', marginBottom: '15px' } }, [
            el(TextControl, {
              label: __('First Activated', 'vapt-builder'),
              value: currentDomain.first_activated_at ? formatDate(currentDomain.first_activated_at) : __('Not Activated', 'vapt-builder'),
              readOnly: true,
              style: { background: '#f8fafc', color: '#64748b' }
            }),
            el(TextControl, {
              label: __('Expiry Date', 'vapt-builder'),
              value: currentDomain.license_type === 'developer'
                ? __('Never Expires', 'vapt-builder')
                : (currentDomain.manual_expiry_date ? formatDate(currentDomain.manual_expiry_date) : ''),
              readOnly: true,
              style: {
                background: '#f8fafc',
                color: (currentDomain.license_type !== 'developer' && currentDomain.manual_expiry_date && new Date(currentDomain.manual_expiry_date) < new Date()) ? '#dc2626' : '#64748b'
              }
            })
          ]),

          el('div', { className: 'components-base-control', style: { marginBottom: '15px' } }, [
            el('div', { style: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: '#f8fafc', border: '1px solid #949494', borderRadius: '4px', padding: '0 12px', height: '40px' } }, [
              el('span', { style: { color: '#1e1e1e', fontSize: '13px', fontWeight: 500 } }, __('Terms Renewed', 'vapt-builder')),
              el('span', { style: { color: '#64748b', fontSize: '13px' } }, `${currentDomain.renewals_count || 0} Times`)
            ])
          ]),

          el('div', { className: 'vapt-desc-text' },
            currentDomain.license_type === 'developer'
              ? __('Developer License: Perpetual access with no expiration.', 'vapt-builder')
              : (currentDomain.license_type === 'pro'
                ? __('Pro License: Annual renewal cycle with premium features.', 'vapt-builder')
                : __('Standard License: 30-day renewal cycle.', 'vapt-builder'))
          ),

          localStatus && el('div', {
            style: {
              marginTop: '15px',
              padding: '8px',
              borderRadius: '4px',
              background: localStatus.type === 'error' ? '#fde8e8' : '#def7ec',
              color: localStatus.type === 'error' ? '#9b1c1c' : '#03543f',
              fontSize: '12px', textAlign: 'center'
            }
          }, localStatus.message)
        ]),

        // RIGHT: Update Form
        el('div', { className: 'vapt-license-card' }, [
          el('h3', null, __('Add License', 'vapt-builder')),

          el('div', { style: { display: 'flex', alignItems: 'flex-end', gap: '10px', marginBottom: '15px' } }, [
            el('div', { style: { flex: 2 } }, (Array.isArray(domains) && domains.length > 1)
              ? el(SelectControl, {
                label: __('Domain Name (Select to Manage)', 'vapt-builder'),
                value: selectedDomainId,
                options: domains.map(d => ({ label: d.domain, value: d.id })),
                onChange: (val) => {
                  setSelectedDomainId(val);
                  fetchData(undefined, true);
                },
                disabled: isSaving,
                style: { marginBottom: 0 }
              })
              : el(TextControl, {
                label: __('Domain Name', 'vapt-builder'),
                value: currentDomain.domain,
                readOnly: true,
                style: { marginBottom: 0, background: '#f8fafc', color: '#64748b' }
              })
            ),

            el('div', { style: { flex: 1, minWidth: '120px' } }, el(TextControl, {
              label: __('Domain Type', 'vapt-builder'),
              value: (currentDomain.is_wildcard === true || currentDomain.is_wildcard == 1 || currentDomain.is_wildcard === '1') ? 'Wildcard' : 'Standard',
              readOnly: true,
              style: { marginBottom: 0, background: '#f8fafc', color: '#64748b' }
            }))
          ]),

          el('div', { style: { display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '15px' } }, [
            el(SelectControl, {
              label: __('License Type', 'vapt-builder'),
              value: formState.license_type,
              disabled: isSaving,
              options: [
                { label: 'Standard (30 Days)', value: 'standard' },
                { label: 'Pro (One Year)', value: 'pro' },
                { label: 'Developer (Perpetual)', value: 'developer' }
              ],
              onChange: (val) => {
                const baseDate = new Date();
                let durationDays = 30;
                if (val === 'pro') durationDays = 365;
                if (val === 'developer') durationDays = 36500;

                baseDate.setDate(baseDate.getDate() + durationDays);
                const newExpiry = baseDate.toISOString().split('T')[0];

                setFormState({
                  ...formState,
                  license_type: val,
                  manual_expiry_date: newExpiry
                });
              }
            }),

            formState.license_type !== 'developer'
              ? el(TextControl, {
                label: __('New Expiry Date', 'vapt-builder'),
                type: 'date',
                value: formState.manual_expiry_date,
                disabled: isSaving,
                onChange: (val) => setFormState({ ...formState, manual_expiry_date: val })
              })
              : el(TextControl, {
                label: __('Expiry Status', 'vapt-builder'),
                value: 'Perpetual License',
                readOnly: true,
                disabled: true,
                style: { background: '#f1f5f9', color: '#475569', fontStyle: 'italic' }
              })
          ]),

          el(ToggleControl, {
            label: __('Auto Renew', 'vapt-builder'),
            checked: formState.auto_renew,
            disabled: isSaving,
            onChange: (val) => setFormState({ ...formState, auto_renew: val }),
            help: __('Automatically extend expiry if active.', 'vapt-builder')
          }),

          el('div', { style: { display: 'flex', gap: '20px', marginBottom: '20px', background: '#f8fafc', padding: '15px', borderRadius: '6px' } }, [
            el('div', { style: { flex: 1 } },
              el(SelectControl, {
                label: __('License Scope', 'vapt-builder'),
                value: formState.license_scope,
                options: [
                  { label: __('Single Domain', 'vapt-builder'), value: 'single' },
                  { label: __('Multi-Site', 'vapt-builder'), value: 'multisite' }
                ],
                onChange: (val) => setFormState({ ...formState, license_scope: val })
              })
            ),
            formState.license_scope === 'multisite' && el('div', { style: { flex: 1 } },
              el(TextControl, {
                label: __('Installation Limit', 'vapt-builder'),
                type: 'number',
                min: 1,
                value: formState.installation_limit,
                onChange: (val) => setFormState({ ...formState, installation_limit: parseInt(val) || 1 })
              })
            )
          ]),

          el('div', { style: { display: 'flex', gap: '10px', marginTop: '20px', alignItems: 'center', flexWrap: 'wrap' } }, [
            el(Button, {
              isPrimary: true,
              isBusy: isSaving && !localStatus?.message.includes('Manual'),
              disabled: !isDirty || isSaving,
              onClick: () => handleUpdate(false)
            }, __('Update License', 'vapt-builder')),

            el(Button, {
              isSecondary: true,
              isBusy: isSaving && localStatus?.message.includes('Manual'),
              disabled: formState.auto_renew || isSaving,
              onClick: () => handleUpdate(true)
            }, __('Manual Renew', 'vapt-builder')),

            (currentDomain.renewals_count > 0) && el('div', { className: 'vapt-correction-controls' }, [
              el(Button, {
                className: 'is-link',
                onClick: () => handleRollback('undo')
              }, __('Undo Last', 'vapt-builder')),
              el(Button, {
                className: 'is-link is-destructive',
                onClick: () => handleRollback('reset')
              }, __('Reset Renewals', 'vapt-builder'))
            ])
          ])
        ])
      ]), // End Grid

      // BOTTOM: Domains List Table (Full Width)
      el('div', { className: 'vapt-license-table-wrap', style: { marginTop: '30px', width: '100%', borderTop: '1px solid #ddd', paddingTop: '30px' } }, [
        el('div', { style: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' } }, [
          el('h3', { style: { margin: 0 } }, __('Domain License Directory', 'vapt-builder')),
          el('div', { style: { width: '300px' } }, [
            el(TextControl, {
              placeholder: __('Search domains...', 'vapt-builder'),
              value: searchQuery,
              onChange: (val) => setSearchQuery(val),
              style: { marginBottom: 0 }
            })
          ])
        ]),
        el('table', { className: 'wp-list-table widefat fixed striped' }, [
          el('thead', null, el('tr', null, [
            el('th', {
              className: `manage-column sortable ${sortBy === 'license_id' ? 'sorted ' + sortOrder : ''}`,
              onClick: () => toggleSort('license_id'),
              style: { cursor: 'pointer' }
            }, [
              el('span', null, __('License ID', 'vapt-builder')),
              el('span', { className: 'sorting-indicator' })
            ]),
            el('th', {
              className: `manage-column sortable ${sortBy === 'installation_limit' ? 'sorted ' + sortOrder : ''}`,
              onClick: () => toggleSort('installation_limit'),
              style: { cursor: 'pointer', width: '80px' }
            }, [
              el('span', null, __('Limit', 'vapt-builder')),
              el('span', { className: 'sorting-indicator' })
            ]),
            el('th', {
              className: `manage-column column-primary sortable ${sortBy === 'domain' ? 'sorted ' + sortOrder : ''}`,
              onClick: () => toggleSort('domain'),
              style: { cursor: 'pointer' }
            }, [
              el('span', null, __('Domain', 'vapt-builder')),
              el('span', { className: 'sorting-indicator' })
            ]),
            el('th', {
              className: `manage-column sortable ${sortBy === 'license_type' ? 'sorted ' + sortOrder : ''}`,
              onClick: () => toggleSort('license_type'),
              style: { cursor: 'pointer' }
            }, [
              el('span', null, __('License', 'vapt-builder')),
              el('span', { className: 'sorting-indicator' })
            ]),
            el('th', {
              className: `manage-column sortable ${sortBy === 'first_activated_at' ? 'sorted ' + sortOrder : ''}`,
              onClick: () => toggleSort('first_activated_at'),
              style: { cursor: 'pointer' }
            }, [
              el('span', null, __('Activated At', 'vapt-builder')),
              el('span', { className: 'sorting-indicator' })
            ]),
            el('th', {
              className: `manage-column sortable ${sortBy === 'manual_expiry_date' ? 'sorted ' + sortOrder : ''}`,
              onClick: () => toggleSort('manual_expiry_date'),
              style: { cursor: 'pointer' }
            }, [
              el('span', null, __('Expiry', 'vapt-builder')),
              el('span', { className: 'sorting-indicator' })
            ]),
            el('th', { style: { width: '80px' } }, __('Renewals', 'vapt-builder')),
            el('th', { style: { width: '80px', textAlign: 'right' } }, __('Actions', 'vapt-builder')),
          ])),
          el('tbody', null, sortedDomains.length === 0 ? el('tr', null, el('td', { colSpan: 7 }, __('No domains found.', 'vapt-builder'))) :
            sortedDomains.map((dom) => el('tr', { key: dom.id, className: dom.id == selectedDomainId ? 'is-selected' : '' }, [
              el('td', null, el('code', { style: { fontSize: '11px' } }, dom.license_id || '-')),
              el('td', null, dom.license_id ? el('div', { style: { display: 'flex', alignItems: 'center', gap: '6px' } }, [
                el('span', { style: { background: '#f1f5f9', padding: '2px 8px', borderRadius: '4px', fontSize: '11px', fontWeight: 'bold' } }, dom.installation_limit || 1),
                el(Tooltip, { text: dom.license_scope === 'multisite' ? __('Multi-Site', 'vapt-builder') : __('Single Domain', 'vapt-builder') },
                  el('span', { className: 'dashicons dashicons-editor-help', style: { fontSize: '14px', color: '#94a3b8', cursor: 'help' } })
                )
              ]) : '-'),
              el('td', { className: 'column-primary' }, [
                el('strong', null, dom.domain),
                (dom.is_wildcard == 1) && el('span', { style: { marginLeft: '8px', fontSize: '10px', background: '#f0f0f1', padding: '2px 6px', borderRadius: '10px' } }, __('Wildcard', 'vapt-builder')),
                el('button', { type: 'button', className: 'toggle-row' }, el('span', { className: 'screen-reader-text' }, __('Show more details', 'vapt-builder')))
              ]),
              el('td', null, el('span', { className: `vapt-license-badge ${dom.license_type || 'standard'}` }, (dom.license_type || 'Standard').toUpperCase())),
              el('td', null, dom.first_activated_at ? formatDate(dom.first_activated_at) : '-'),
              el('td', null, dom.license_type === 'developer' ? __('Never', 'vapt-builder') : (dom.manual_expiry_date ? formatDate(dom.manual_expiry_date) : '-')),
              el('td', null, `${dom.renewals_count || 0}`),
              el('td', { style: { textAlign: 'right' } }, [
                el(Button, { isSecondary: true, isSmall: true, onClick: () => handleEdit(dom) }, __('Edit', 'vapt-builder'))
              ])
            ]))
          )
        ])
      ]),

      // Confirmation Modal
      el(VAPT_ConfirmModal, {
        isOpen: confirmState.isOpen,
        message: confirmState.type === 'undo'
          ? __('Are you sure you want to undo the last manual renewal?', 'vapt-builder')
          : __('Are you sure you want to reset all consecutive manual renewals?', 'vapt-builder'),
        onConfirm: executeRollback,
        onCancel: () => setConfirmState({ isOpen: false, type: null }),
        confirmLabel: __('Revert Now', 'vapt-builder'),
        isDestructive: confirmState.type === 'reset'
      })
    ]);
  };

  const generateDevInstructions = (f) => {
    if (!f) return '';

    const lines = [];
    const baseUrl = window.location.origin;

    // 1. Identity & Context
    lines.push(`## 1. Identity & Context`);
    lines.push(`- **Risk ID**: ${f.risk_id || f.key || 'N/A'}`);
    lines.push(`- **Title**: ${f.title || f.label || 'N/A'}`);
    lines.push(`- **Category**: ${f.category || 'General'}`);
    lines.push(`- **Severity**: ${f.severity || 'Medium'}`);
    if (f.cvss_score) lines.push(`- **CVSS**: ${f.cvss_score} (${f.cvss_vector || 'N/A'})`);

    // 2. Summary & Description
    if (f.description) {
      if (typeof f.description === 'string') lines.push(`\n**Summary**: ${f.description}`);
      else {
        if (f.description.summary) lines.push(`\n**Summary**: ${f.description.summary}`);
        if (f.description.detailed) lines.push(`\n**Detailed Analysis**:\n${f.description.detailed}`);
      }
    }
    if (f.attack_scenario) lines.push(`\n**Attack Scenario**:\n${f.attack_scenario}`);

    // 3. Compliance
    if (f.owasp_mapping || f.pci_dss || f.gdpr || f.nist || f.cwe) {
      lines.push(`\n## 2. Compliance Mapping`);
      if (f.owasp_mapping) lines.push(`- **OWASP**: ${Array.isArray(f.owasp_mapping) ? f.owasp_mapping.join(', ') : f.owasp_mapping}`);
      if (f.pci_dss) lines.push(`- **PCI DSS**: ${Array.isArray(f.pci_dss) ? f.pci_dss.join(', ') : f.pci_dss}`);
      if (f.gdpr) lines.push(`- **GDPR**: ${Array.isArray(f.gdpr) ? f.gdpr.join(', ') : f.gdpr}`);
      if (f.nist) lines.push(`- **NIST**: ${Array.isArray(f.nist) ? f.nist.join(', ') : f.nist}`);
      if (f.cwe) lines.push(`- **CWE**: ${Array.isArray(f.cwe) ? f.cwe.join(', ') : f.cwe}`);
    }

    // 4. Technical Protection & Mitigation
    lines.push(`\n## 3. Technical Protection & Mitigation`);
    if (f.protection) {
      const p = f.protection;
      if (p.remediation_effort) lines.push(`- **Effort**: ${p.remediation_effort}`);
      if (p.estimated_time) lines.push(`- **Est. Time**: ${p.estimated_time}`);

      if (p.automated_protection) {
        lines.push(`\n### Automated Protection`);
        lines.push(`- **Method**: ${p.automated_protection.method}`);
        if (p.automated_protection.implementation_steps) {
          lines.push(`- **Implementation Steps**:`);
          const steps = Array.isArray(p.automated_protection.implementation_steps) ? p.automated_protection.implementation_steps : [p.automated_protection.implementation_steps];
          steps.forEach(s => lines.push(`  - ${s}`));
        }
      }
      if (p.manual_steps) {
        lines.push(`\n### Manual Steps`);
        lines.push(`${p.manual_steps.description || JSON.stringify(p.manual_steps)}`);
      }
      if (p.configuration) {
        lines.push(`\n### Configuration`);
        if (p.configuration.wp_config) lines.push(`- **wp-config.php**: \`${p.configuration.wp_config}\``);
        if (p.configuration.htaccess) lines.push(`- **.htaccess**: \`${p.configuration.htaccess}\``);
      }
    }

    // 5. Verification Engine
    if (f.verification_engine) {
      lines.push(`\n## 4. Verification Engine`);
      if (f.verification_engine.automated_checks) {
        lines.push(`### Automated Checks`);
        const checks = Array.isArray(f.verification_engine.automated_checks) ? f.verification_engine.automated_checks : [f.verification_engine.automated_checks];
        checks.forEach(c => {
          lines.push(`- **${c.check_id || 'Check'}**: ${c.name}`);
          lines.push(`  - Method: ${c.method}`);
          lines.push(`  - Success: ${c.success_criteria}`);
          lines.push(`  - Fail: ${c.failure_message}`);
        });
      }
    }

    // 6. QA & Testing Protocol
    lines.push(`\n## 5. QA & Testing Protocol`);
    if (f.testing) {
      const t = f.testing;
      if (t.test_method) lines.push(`- **Method**: ${t.test_method}`);
      if (t.tools_required) lines.push(`- **Tools**: ${Array.isArray(t.tools_required) ? t.tools_required.join(', ') : t.tools_required}`);
      if (t.verification_steps) {
        lines.push(`\n### Verification Steps`);
        const vSteps = Array.isArray(t.verification_steps) ? t.verification_steps : [t.verification_steps];
        vSteps.forEach(s => lines.push(`- ${s}`));
      }
      if (t.test_payloads) {
        lines.push(`\n### Test Payloads`);
        const payloads = Array.isArray(t.test_payloads) ? t.test_payloads : [t.test_payloads];
        payloads.forEach(p => {
          let payloadStr = p.payload;
          if (payloadStr && payloadStr.startsWith('/')) {
            payloadStr = baseUrl + payloadStr;
          }
          lines.push(`- \`${payloadStr}\` (${p.type}) -> ${p.expected_behavior}`);
        });
      }
    }

    // 7. UI Configuration
    if (f.ui_configuration) {
      lines.push(`\n## 6. UI Implementation Guide`);
      const ui = f.ui_configuration;
      if (ui.components) {
        const comps = Array.isArray(ui.components) ? ui.components : [ui.components];
        comps.forEach(c => {
          lines.push(`- **${c.label}** (${c.type})`);
          lines.push(`  - ID: \`${c.id}\``);
          if (c.description) lines.push(`  - Desc: ${c.description}`);
          if (c.default_value !== undefined) lines.push(`  - Default: ${c.default_value}`);
        });
      }
    }

    // 8. Code Examples
    if (f.code_examples) {
      lines.push(`\n## 7. Reference Code`);
      const ex = Array.isArray(f.code_examples) ? f.code_examples : [f.code_examples];
      ex.forEach(c => {
        lines.push(`### ${c.description || 'Example'}`);
        lines.push(`\`\`\`${c.language || 'php'}\n${c.code}\n\`\`\``);
      });
    }

    // 9. Safety & Reliability Guidelines (CRITICAL)
    lines.push(`\n## 8. Safety & Reliability Guidelines`);

    // Dynamic Context Analysis
    const lowerTitle = (f.title || '').toLowerCase();
    const lowerDesc = (typeof f.description === 'string' ? f.description : (f.description?.summary || '')).toLowerCase();
    const verificationStr = JSON.stringify(f.verification_steps || []).toLowerCase();
    const payloadsStr = JSON.stringify(f.testing?.test_payloads || []).toLowerCase();
    const combinedContext = lowerTitle + lowerDesc + verificationStr + payloadsStr;

    lines.push(`### Implementation Strategy (Context-Driven)`);

    // 1. REST API Scope
    if (combinedContext.includes('/wp-json/') || combinedContext.includes('rest api')) {
      lines.push(`- **Scope Detected**: REST API / JSON Endpoint`);
      lines.push(`- **Mandatory Hook**: \`rest_authentication_errors\``);
      lines.push(`- **Action**: Return \`new WP_Error('rest_forbidden', 'Forbidden', { status: 403 })\`.`);
      lines.push(`- **Constraint**: DO NOT use \`template_redirect\` for API requests (it may not fire or return HTML instead of JSON).`);
    }

    // 2. Authentication Scope
    if (combinedContext.includes('login') || combinedContext.includes('auth') || combinedContext.includes('password')) {
      lines.push(`- **Scope Detected**: Authentication System`);
      lines.push(`- **Mandatory Hook**: \`authenticate\` filter (priority 30+) or \`login_init\`.`);
      lines.push(`- **Action**: Return \`WP_Error\` for blocking conditions.`);
    }

    // 3. Author / User Enumeration Scope
    if (combinedContext.includes('author=') || combinedContext.includes('is_author')) {
      lines.push(`- **Scope Detected**: Author Archives`);
      lines.push(`- **Mandatory Hook**: \`template_redirect\``);
      lines.push(`- **Condition**: Check \`is_author()\` or \`$_GET['author']\`.`);
    }

    lines.push(`\n### General Reliability Rules`);
    lines.push(`- **Status Code**: STRICTLY enforce HTTP 403 for blocked requests. 200 OK is a failure.`);
    lines.push(`- **Error Handling**: Wrap critical logic. Avoid PHP Fatal Errors (HTTP 500).`);
    lines.push(`- **Standardization**: Use \`wp_die()\` for HTML pages, \`WP_Error\` for API.`);
    lines.push(`- **Bypass Prevention**: Ensure disabling the feature (via toggle) completely removes the hook.`);

    return lines.join('\n');
  };

  const FeatureList = ({
    features, schema, updateFeature, loading, dataFiles, selectedFile, onSelectFile, onUpload, allFiles, hiddenFiles, onUpdateHiddenFiles, manageSourcesStatus, isManageModalOpen, setIsManageModalOpen, onRemoveFile, designPromptConfig, setDesignPromptConfig,
    historyFeature, setHistoryFeature, designFeature, setDesignFeature, transitioning, setTransitioning, isPromptConfigModalOpen, setIsPromptConfigModalOpen, isMappingModalOpen, setIsMappingModalOpen,
    sortBySource, setSortBySource, sortSourceDirection, setSortSourceDirection
  }) => {
    const [confirmingFile, setConfirmingFile] = useState(null);
    const [columnOrder, setColumnOrder] = useState(() => {
      const saved = localStorage.getItem(`vapt_col_order_${selectedFile}`);
      return saved ? JSON.parse(saved) : ['title', 'category', 'severity', 'description'];
    });

    const [visibleCols, setVisibleCols] = useState(() => {
      const saved = localStorage.getItem(`vapt_visible_cols_${selectedFile}`);
      return saved ? JSON.parse(saved) : ['title', 'category', 'severity', 'description'];
    });

    // Update column defaults when schema changes if not already set
    useEffect(() => {
      const savedOrder = localStorage.getItem(`vapt_col_order_${selectedFile} `);
      const savedVisible = localStorage.getItem(`vapt_visible_cols_${selectedFile} `);

      console.log('[VAPT] Init Check:', { selectedFile, savedOrder: !!savedOrder, savedVisible: !!savedVisible });

      if (!savedOrder && schema?.item_fields) {
        console.log('[VAPT] Applying default order');
        setColumnOrder(['title', 'category', 'severity', 'description']);
      }
      if (!savedVisible && schema?.item_fields) {
        console.log('[VAPT] Applying default visibility');
        setVisibleCols(['title', 'category', 'severity', 'description']);
      }
    }, [schema, selectedFile]);

    // Effective columns to show in table
    const activeCols = columnOrder.filter(c => visibleCols.includes(c));

    useEffect(() => {
      localStorage.setItem(`vapt_col_order_${selectedFile} `, JSON.stringify(columnOrder));
      localStorage.setItem(`vapt_visible_cols_${selectedFile} `, JSON.stringify(visibleCols));
    }, [columnOrder, visibleCols, selectedFile]);

    const [filterStatus, setFilterStatus] = useState(() => localStorage.getItem('vapt_filter_status') || 'all');
    const [selectedCategories, setSelectedCategories] = useState(() => {
      const saved = localStorage.getItem('vapt_selected_categories');
      return saved ? JSON.parse(saved) : [];
    });

    // Local Save Status for Columns
    const [colSaveStatus, setColSaveStatus] = useState(null);
    const isFirstMount = wp.element.useRef(true);

    useEffect(() => {
      if (isFirstMount.current) {
        isFirstMount.current = false;
        return;
      }
      localStorage.setItem(`vapt_col_order_${selectedFile} `, JSON.stringify(columnOrder));
      localStorage.setItem(`vapt_visible_cols_${selectedFile} `, JSON.stringify(visibleCols));
      setColSaveStatus('Saved');
      const timer = setTimeout(() => setColSaveStatus(null), 2000);
      return () => clearTimeout(timer);
    }, [columnOrder, visibleCols, selectedFile]);

    // Drag and Drop State
    const [draggedCol, setDraggedCol] = useState(null);

    const handleDragStart = (e, col) => {
      setDraggedCol(col);
      e.dataTransfer.effectAllowed = 'move';
      // e.target.style.opacity = '0.5'; 
    };

    const handleDragOver = (e) => {
      e.preventDefault();
      e.dataTransfer.dropEffect = 'move';
    };

    const handleDrop = (e, targetCol) => {
      e.preventDefault();
      if (draggedCol === targetCol) return;

      const newOrder = [...columnOrder];
      const draggedIdx = newOrder.indexOf(draggedCol);
      const targetIdx = newOrder.indexOf(targetCol);

      newOrder.splice(draggedIdx, 1);
      newOrder.splice(targetIdx, 0, draggedCol);

      setColumnOrder(newOrder);
      setDraggedCol(null);
    };

    const [selectedSeverities, setSelectedSeverities] = useState(() => {
      const saved = localStorage.getItem('vapt_selected_severities');
      return saved ? JSON.parse(saved) : [];
    });
    const [sortBy, setSortBy] = useState(() => localStorage.getItem('vapt_sort_by') || 'name');
    const [sortOrder, setSortOrder] = useState(() => localStorage.getItem('vapt_sort_order') || 'asc');
    const [searchQuery, setSearchQuery] = useState(() => localStorage.getItem('vapt_search_query') || '');
    const [fieldMapping, setFieldMapping] = useState({ test_method: '', verification_steps: '', verification_engine: '' });


    // Load/Save Field Mapping per File
    useEffect(() => {
      if (!selectedFile) return;
      const saved = localStorage.getItem(`vapt_field_mapping_${selectedFile}`);
      if (saved) {
        setFieldMapping(JSON.parse(saved));
      } else {
        setFieldMapping({ test_method: '', verification_steps: '', verification_engine: '' });
      }
    }, [selectedFile]);

    useEffect(() => {
      if (!selectedFile) return;
      localStorage.setItem(`vapt_field_mapping_${selectedFile}`, JSON.stringify(fieldMapping));
    }, [fieldMapping, selectedFile]);

    const toggleSort = (key) => {
      if (sortBy === key) {
        setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
      } else {
        setSortBy(key);
        setSortOrder('asc');
      }
    };

    // Persist filters
    useEffect(() => {
      localStorage.setItem('vapt_filter_status', filterStatus);
      localStorage.setItem('vapt_selected_categories', JSON.stringify(selectedCategories));
      localStorage.setItem('vapt_selected_severities', JSON.stringify(selectedSeverities));
      localStorage.setItem('vapt_sort_by', sortBy);
      localStorage.setItem('vapt_sort_order', sortOrder);
      localStorage.setItem('vapt_search_query', searchQuery);
    }, [filterStatus, selectedCategories, selectedSeverities, sortBy, sortOrder, searchQuery]);

    const [saveStatus, setSaveStatus] = useState(null); // Feedback for media/clipboard uploads

    // confirmTransition moved to VAPTAdmin to avoid modal flicker when state updates


    // Smart Toggle Handling
    const handleSmartToggle = (feature, toggleKey) => {
      const newVal = !feature[toggleKey];
      let updates = { [toggleKey]: newVal ? 1 : 0 }; // Ensure 1/0 for DB compatibility

      if (newVal) {
        let contentField = null;
        let mappingKey = null;

        if (toggleKey === 'include_test_method') {
          contentField = 'test_method'; mappingKey = 'test_method';
        } else if (toggleKey === 'include_verification') {
          contentField = 'verification_steps'; mappingKey = 'verification_steps';
        } else if (toggleKey === 'include_verification_engine') {
          contentField = 'generated_schema'; mappingKey = 'verification_engine';
        }

        if (contentField && mappingKey && fieldMapping[mappingKey]) {
          // Check if destination is effectively empty
          let isEmpty = !feature[contentField];
          if (Array.isArray(feature[contentField]) && feature[contentField].length === 0) isEmpty = true;
          if (typeof feature[contentField] === 'object' && feature[contentField] !== null && Object.keys(feature[contentField]).length === 0) isEmpty = true;
          // Special check for schema with empty controls
          if (contentField === 'generated_schema' && feature[contentField]?.controls?.length === 0) isEmpty = true;

          if (isEmpty) {
            const sourceKey = fieldMapping[mappingKey];
            let sourceVal = feature[sourceKey];
            if (sourceVal) {
              if (contentField === 'generated_schema' && typeof sourceVal === 'string') {
                try { sourceVal = JSON.parse(sourceVal); } catch (e) {
                  console.warn('VAPT: Failed to parse source JSON for mapping', e);
                }
              }
              updates[contentField] = sourceVal;
              console.log(`VAPT: Smart Mapping populated ${contentField} from ${sourceKey} `);
            }
          }
        }
      }
      updateFeature(feature.key || feature.id, updates);
    };

    // 1. Analytics (Moved below filtering for scope)

    // 2. Extract Categories & Severities & All Keys
    const safeFeatures = Array.isArray(features) ? features : [];
    const categories = [...new Set(safeFeatures.map(f => f.category))].filter(Boolean).sort();
    const severities = [...new Set(safeFeatures.map(f => f.severity))].filter(Boolean);
    const severityOrder = ['critical', 'high', 'medium', 'low', 'informational'];
    const uniqueSeverities = [...new Set(severities.map(s => s.toLowerCase()))]
      .sort((a, b) => severityOrder.indexOf(a) - severityOrder.indexOf(b))
      .map(s => {
        const map = {
          'critical': 'Critical',
          'high': 'High',
          'medium': 'Medium',
          'low': 'Low',
          'informational': 'Informational'
        };
        return map[s] || (s.charAt(0).toUpperCase() + s.slice(1).toLowerCase());
      });

    // Collect all available keys from features data
    const allKeys = [...new Set(safeFeatures.reduce((acc, f) => [...acc, ...Object.keys(f)], []))].filter(k =>
      !['key', 'label', 'status', 'normalized_status', 'has_history', 'include_test_method', 'include_verification', 'include_verification_engine', 'wireframe_url', 'generated_schema', 'implemented_at', 'assigned_to'].includes(k)
    );

    // Update columnOrder if new keys are found that aren't in there
    useEffect(() => {
      const missingKeys = allKeys.filter(k => !columnOrder.includes(k));
      if (missingKeys.length > 0) {
        setColumnOrder([...columnOrder, ...missingKeys]);
      }
    }, [allKeys, columnOrder]);

    // 3. Filter & Sort
    let processedFeatures = [...safeFeatures];

    // Category Filter First
    if (selectedCategories.length > 0) {
      processedFeatures = processedFeatures.filter(f => selectedCategories.includes(f.category));
    }

    // Severity Filter (Case-Insensitive)
    if (selectedSeverities.length > 0) {
      const lowSelected = selectedSeverities.map(s => s.toLowerCase());
      processedFeatures = processedFeatures.filter(f => f.severity && lowSelected.includes(f.severity.toLowerCase()));
    }

    const stats = {
      unfilteredTotal: safeFeatures.length,
      total: processedFeatures.length,
      draft: processedFeatures.filter(f => f.status === 'Draft').length,
      develop: processedFeatures.filter(f => f.status === 'Develop').length,
      test: processedFeatures.filter(f => f.status === 'Test').length,
      release: processedFeatures.filter(f => f.status === 'Release').length
    };

    const resetFilters = () => {
      setSelectedCategories([]);
      setSelectedSeverities([]);
      setFilterStatus('all');
      setSearchQuery('');
    };

    // Status Filter Second
    if (filterStatus !== 'all') {
      processedFeatures = processedFeatures.filter(f => {
        // Handle legacy lowercase filters from localStorage
        const s = filterStatus.toLowerCase();
        if (s === 'draft') return f.status === 'Draft';
        if (s === 'develop') return f.status === 'Develop';
        if (s === 'test') return f.status === 'Test';
        if (s === 'release') return f.status === 'Release';
        return f.status === filterStatus;
      });
    }

    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      processedFeatures = processedFeatures.filter(f =>
        (f.name || f.label).toLowerCase().includes(q) ||
        (f.description && f.description.toLowerCase().includes(q))
      );
    }

    processedFeatures.sort((a, b) => {
      // Primary Sort: Data Source
      if (sortBySource) {
        const getSourceWeight = (f) => {
          if (f.exists_in_multiple_files) return 3;
          if (f.is_from_active_file !== false) return 2;
          return 1;
        };
        const wA = getSourceWeight(a);
        const wB = getSourceWeight(b);
        if (wA !== wB) {
          return sortSourceDirection === 'asc' ? (wA - wB) : (wB - wA);
        }
      }

      // Secondary Sort: Column Headers (Existing Logic)
      const nameA = (a.name || a.label || '').toLowerCase();
      const nameB = (b.name || b.label || '').toLowerCase();
      const catA = (a.category || '').toLowerCase();
      const catB = (b.category || '').toLowerCase();

      const sevPriority = { 'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'informational': 0 };
      const sevA = sevPriority[(a.severity || '').toLowerCase()] || 0;
      const sevB = sevPriority[(b.severity || '').toLowerCase()] || 0;

      let comparison = 0;
      if (sortBy === 'name' || sortBy === 'title') comparison = nameA.localeCompare(nameB);
      else if (sortBy === 'category') comparison = catA.localeCompare(catB);
      else if (sortBy === 'severity') comparison = sevA - sevB;

      else if (sortBy === 'status') {
        const priority = {
          'Release': 4,
          'Test': 3,
          'Develop': 2,
          'Draft': 1
        };
        comparison = (priority[a.status] || 0) - (priority[b.status] || 0);
      }

      return sortOrder === 'asc' ? comparison : -comparison;
    });



    return el('div', { id: 'vapt-feature-list-tab', className: 'vapt-feature-list-tab-wrap' }, [
      el(PanelBody, { id: 'vapt-feature-list-panel', title: __('Exhaustive Feature List', 'vapt-builder'), initialOpen: true }, [
        // Top Controls & Unified Header
        el('div', { id: 'vapt-feature-list-header-controls', key: 'controls', style: { marginBottom: '10px' } }, [
          // Unified Header Block (Source, Columns, Manage, Upload)
          el('div', {
            id: 'vapt-feature-list-toolbar',
            className: 'vapt-toolbar-block'
          }, [
            // Branded Icon with Configure Columns Dropdown
            el(Dropdown, {
              renderToggle: ({ isOpen, onToggle }) => el('div', {
                id: 'vapt-btn-configure-columns',
                onClick: onToggle,
                className: 'vapt-toolbar-btn-icon',
                'aria-expanded': isOpen,
                title: __('Configure Table Columns', 'vapt-builder')
              }, el(Icon, { icon: 'layout', size: 18 })),
              renderContent: ({ onClose }) => {
                const activeFields = columnOrder.filter(c => visibleCols.includes(c) && allKeys.includes(c));
                const availableFields = allKeys.filter(c => !visibleCols.includes(c));
                const half = Math.ceil(availableFields.length / 2);
                const availableCol1 = availableFields.slice(0, half);
                const availableCol2 = availableFields.slice(half);

                return el('div', { style: { padding: '20px', width: '850px' } }, [
                  el('h4', { style: { marginTop: 0, marginBottom: '5px', display: 'flex', alignItems: 'center', justifyContent: 'space-between' } }, [
                    sprintf(__('Configure Table Columns: %s', 'vapt-builder'), selectedFile),
                    el('div', { style: { display: 'flex', alignItems: 'center', gap: '15px' } }, [
                      colSaveStatus && el('span', { style: { fontSize: '11px', color: '#00a32a', fontWeight: 'bold' } }, __('Saved to Browser', 'vapt-builder')),
                      el(Button, {
                        isSecondary: true,
                        isSmall: true,
                        onClick: onClose,
                        style: { height: '24px', lineHeight: '1' }
                      }, __('Close', 'vapt-builder'))
                    ])
                  ]),
                  el('p', { style: { fontSize: '12px', color: '#666', marginBottom: '20px' } }, __('Confirm the table sequence and add/remove fields.', 'vapt-builder')),
                  el('div', { style: { display: 'grid', gridTemplateColumns: 'minmax(280px, 1.2fr) 1fr 1fr', gap: '25px' } }, [
                    el('div', null, [
                      el('h5', { style: { margin: '0 0 10px 0', fontSize: '11px', textTransform: 'uppercase', color: '#2271b1', fontWeight: 'bold' } }, __('Active Table Sequence', 'vapt-builder')),
                      el('div', { style: { display: 'flex', flexDirection: 'column', gap: '6px' } },
                        activeFields.map((field, activeIdx) => {
                          const masterIdx = columnOrder.indexOf(field);
                          return el('div', {
                            key: field,
                            draggable: true,
                            onDragStart: (e) => handleDragStart(e, field),
                            onDragOver: handleDragOver,
                            onDrop: (e) => handleDrop(e, field),
                            style: {
                              display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                              padding: '6px 10px',
                              background: draggedCol === field ? '#eef' : '#f0f6fb',
                              borderRadius: '4px',
                              border: '1px solid #c8d7e1',
                              cursor: 'grab',
                              opacity: draggedCol === field ? 0.5 : 1,
                              transition: 'all 0.2s'
                            }
                          }, [
                            el('div', { style: { display: 'flex', alignItems: 'center', gap: '8px' } }, [
                              el('span', { className: 'dashicons dashicons-menu', style: { color: '#aaa', cursor: 'grab', fontSize: '16px' } }),
                              el('span', { style: { fontSize: '10px', fontWeight: 'bold', color: '#72777c', minWidth: '20px' } }, `#${activeIdx + 1}`),
                              el(CheckboxControl, {
                                label: field.charAt(0).toUpperCase() + field.slice(1).replace(/_/g, ' '),
                                checked: true,
                                onChange: () => setVisibleCols(visibleCols.filter(c => c !== field)),
                                __nextHasNoMarginBottom: true,
                                __next40pxDefaultSize: true,
                                style: { margin: 0 }
                              })
                            ])
                          ]);
                        })
                      )]),
                    el('div', null, [
                      el('h5', { style: { margin: '0 0 10px 0', fontSize: '11px', textTransform: 'uppercase', color: '#666', fontWeight: 'bold' } }, __('Available Fields', 'vapt-builder')),
                      el('div', { style: { display: 'flex', flexDirection: 'column', gap: '6px' } },
                        availableCol1.map((field) => (
                          el('div', { key: field, style: { display: 'flex', alignItems: 'center', padding: '6px 10px', background: '#fff', borderRadius: '4px', border: '1px solid #e1e1e1' } }, [
                            el(CheckboxControl, {
                              label: field.charAt(0).toUpperCase() + field.slice(1).replace(/_/g, ' '),
                              checked: false,
                              onChange: () => setVisibleCols([...visibleCols, field]),
                              style: { margin: 0 }
                            })
                          ])
                        ))
                      )
                    ]),
                    el('div', null, [
                      el('h5', { style: { margin: '0 0 10px 0', fontSize: '11px', textTransform: 'uppercase', color: '#666', fontWeight: 'bold' } }, __('Available Fields', 'vapt-builder')),
                      el('div', { style: { display: 'flex', flexDirection: 'column', gap: '6px' } },
                        availableCol2.map((field) => (
                          el('div', { key: field, style: { display: 'flex', alignItems: 'center', padding: '6px 10px', background: '#fff', borderRadius: '4px', border: '1px solid #e1e1e1' } }, [
                            el(CheckboxControl, {
                              label: field.charAt(0).toUpperCase() + field.slice(1).replace(/_/g, ' '),
                              checked: false,
                              onChange: () => setVisibleCols([...visibleCols, field]),
                              style: { margin: 0 }
                            })
                          ])
                        ))
                      )
                    ])
                  ]),
                  el('div', { style: { marginTop: '20px', borderTop: '1px solid #eee', paddingTop: '10px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' } }, [
                    el('span', { style: { fontSize: '11px', color: '#949494' } }, sprintf(__('%d Columns active, %d Available', 'vapt-builder'), activeFields.length, availableFields.length)),
                    el(Button, {
                      isLink: true, isDestructive: true,
                      onClick: () => {
                        const defaultFields = ['title', 'category', 'severity', 'description'];
                        setColumnOrder(defaultFields);
                        setVisibleCols(defaultFields);
                      }
                    }, __('Reset to Default', 'vapt-builder'))
                  ])
                ]);
              }
            }),

            // Map Include Fields Button
            el(Button, {
              isSecondary: true,
              isSmall: true,
              icon: 'networking', // Using networking to represent mapping
              onClick: () => setIsMappingModalOpen(true),
              style: { marginLeft: '5px', fontSize: '11px', height: '30px', minHeight: '30px', boxSizing: 'border-box', lineHeight: '1' }
            }, __('Map Include Fields', 'vapt-builder')),

            // Feature Source Selection
            // Feature Source Selection (Checkbox Style)
            el('div', {
              style: {
                flexGrow: 1,
                paddingLeft: '12px',
                display: 'flex',
                alignItems: 'center',
                gap: '12px'
              }
            }, [
              // Data Sources Label
              // el('span', { style: { fontWeight: '700', textTransform: 'uppercase', fontSize: '9px', color: '#64748b' } }, __('Data Sources:', 'vapt-builder')),

              // Checkbox Container
              el('div', { style: { display: 'flex', gap: '12px', flexWrap: 'wrap' } }, [
                // "All Data Files" Option (Only show for 3+ files)
                dataFiles.length >= 3 && el('label', {
                  key: 'all-files',
                  style: {
                    display: 'flex',
                    alignItems: 'center',
                    gap: '4px',
                    cursor: 'pointer',
                    fontSize: '11px',
                    fontWeight: (selectedFile || '').split(',').includes('__all__') ? '700' : '500',
                    color: (selectedFile || '').split(',').includes('__all__') ? '#1e3a8a' : '#64748b'
                  }
                }, [
                  el('input', {
                    type: 'checkbox',
                    checked: (selectedFile || '').split(',').includes('__all__'),
                    onChange: () => onSelectFile('__all__'),
                    style: { margin: 0, width: '13px', height: '13px' }
                  }),
                  __('All Data Files', 'vapt-builder')
                ]),
                // Individual Files
                ...dataFiles.map(file => {
                  const isAllSelected = (selectedFile || '').split(',').includes('__all__');
                  const currentFiles = (selectedFile || '').split(',').filter(f => f && f !== '__all__');
                  const isChecked = isAllSelected || currentFiles.includes(file.value);
                  const isLastSelected = isChecked && currentFiles.length === 1 && currentFiles.includes(file.value);
                  const isDisabled = isAllSelected || isLastSelected;

                  return el('label', {
                    key: file.value,
                    title: isDisabled ? (isLastSelected ? __('At least one source must be selected.', 'vapt-builder') : '') : '',
                    style: {
                      display: 'flex',
                      alignItems: 'center',
                      gap: '4px',
                      cursor: isDisabled ? 'default' : 'pointer',
                      fontSize: '11px',
                      fontWeight: isChecked ? '700' : '500',
                      color: isChecked ? '#1e3a8a' : '#64748b',
                      opacity: isDisabled ? 0.6 : 1
                    }
                  }, [
                    el('input', {
                      type: 'checkbox',
                      checked: isChecked,
                      disabled: isDisabled,
                      onChange: () => !isDisabled && onSelectFile(file.value),
                      style: {
                        margin: 0,
                        width: '13px',
                        height: '13px',
                        pointerEvents: isDisabled ? 'none' : 'auto',
                        cursor: isDisabled ? 'default' : 'pointer'
                      }
                    }),
                    file.label
                  ]);
                })
              ])
            ]),

            // Sort Control
            el('div', { style: { borderLeft: '1px solid #dcdcde', paddingLeft: '12px', display: 'flex', alignItems: 'center', gap: '8px' } }, [
              el(CheckboxControl, {
                label: __('Sort by Data Source', 'vapt-builder'),
                checked: sortBySource,
                onChange: (val) => setSortBySource(val),
                className: 'vapt-sort-checkbox',
                __nextHasNoMarginBottom: true,
                style: { margin: 0 } // Explicitly remove margin for alignment
              }),
              sortBySource && el(Button, {
                icon: sortSourceDirection === 'asc' ? 'arrow-up' : 'arrow-down',
                label: sortSourceDirection === 'asc' ? __('Ascending', 'vapt-builder') : __('Descending', 'vapt-builder'),
                onClick: () => setSortSourceDirection(sortSourceDirection === 'asc' ? 'desc' : 'asc'),
                style: { minWidth: '24px', padding: 0, height: '24px', marginLeft: '-4px' }
              })
            ]),

            // Manage Sources Trigger
            el('div', { style: { borderLeft: '1px solid #dcdcde', paddingLeft: '12px', display: 'flex', alignItems: 'center' } }, [
              el(Button, {
                isSecondary: true,
                icon: 'admin-settings',
                onClick: () => setIsManageModalOpen(true),
                label: __('Manage Sources', 'vapt-builder'),
                style: { height: '30px', minHeight: '30px', width: '30px', border: '1px solid #2271b1', color: '#2271b1', boxSizing: 'border-box', padding: 0 }
              })
            ]),

            // Upload Section
            el('div', { style: { borderLeft: '1px solid #dcdcde', paddingLeft: '12px', display: 'flex', flexDirection: 'column' } }, [
              // Label removed per user request
              el('input', {
                type: 'file',
                accept: '.json',
                onChange: (e) => e.target.files.length > 0 && onUpload(e.target.files[0]),
                style: { fontSize: '11px', color: '#555', height: '30px', padding: '4px 0', boxSizing: 'border-box' }
              })
            ])
          ]),

          // Manage Sources Modal
          isManageModalOpen && el(Modal, {
            title: __('Manage JSON Sources', 'vapt-builder'),
            onRequestClose: () => setIsManageModalOpen(false)
          }, [
            el('p', null, __('Deselect files to hide them from the Feature Source dropdown. The active file cannot be hidden.', 'vapt-builder')),
            el('div', { style: { maxHeight: '400px', overflowY: 'auto' } }, [
              allFiles.map(file => el('div', {
                key: file.filename,
                style: { display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '5px 0', borderBottom: '1px solid #eee' }
              }, [
                el(CheckboxControl, {
                  label: file.display_name || file.filename.replace(/_/g, ' '),
                  checked: !hiddenFiles.includes(file.filename),
                  disabled: file.filename === selectedFile,
                  onChange: (val) => {
                    const newHidden = val
                      ? hiddenFiles.filter(h => h !== file.filename)
                      : [...hiddenFiles, file.filename];
                    onUpdateHiddenFiles(newHidden);
                  }
                }),
                el(Button, {
                  icon: 'no',
                  isDestructive: true,
                  isSmall: true,
                  disabled: file.filename === selectedFile,
                  onClick: () => setConfirmingFile(file.filename),
                  label: __('Remove from list', 'vapt-builder'),
                  style: { marginLeft: '10px' }
                })
              ]))
            ]),
            confirmingFile && el(Modal, {
              title: __('Confirm Removal', 'vapt-builder'),
              onRequestClose: () => setConfirmingFile(null),
              className: 'vapt-confirm-modal',
              overlayClassName: 'vapt-confirm-modal-overlay'
            }, [
              el('p', null, __('Are you sure you want to remove this source from the list? The physical file will remains on the server as a backup and can be restored by re-uploading.', 'vapt-builder')),
              el('div', { style: { display: 'flex', justifyContent: 'flex-end', gap: '10px', marginTop: '20px' } }, [
                el(Button, {
                  isSecondary: true,
                  onClick: () => setConfirmingFile(null)
                }, __('Cancel', 'vapt-builder')),
                el(Button, {
                  isPrimary: true,
                  isDestructive: true,
                  onClick: () => {
                    onRemoveFile(confirmingFile);
                    setConfirmingFile(null);
                  }
                }, __('Confirm Removal', 'vapt-builder'))
              ])
            ]),
            el('div', { style: { marginTop: '20px', textAlign: 'right', display: 'flex', alignItems: 'center', justifyContent: 'flex-end', gap: '10px' } }, [
              manageSourcesStatus === 'saving' && el(Spinner),
              manageSourcesStatus === 'saved' && el('span', { style: { color: '#00a32a', fontWeight: 'bold' } }, __('Saved', 'vapt-builder')),
              el(Button, { isPrimary: true, onClick: () => setIsManageModalOpen(false) }, __('Close', 'vapt-builder'))
            ])
          ]),

          // Summary Pill Row
          el('div', {
            style: {
              display: 'flex',
              gap: '15px',
              padding: '6px 15px',
              background: '#fff',
              border: '1px solid #dcdcde',
              borderRadius: '4px',
              marginBottom: '10px',
              alignItems: 'center',
              fontSize: '11px',
              color: '#333'
            }
          }, [
            el('span', { style: { fontWeight: '700', textTransform: 'uppercase', fontSize: '10px', color: '#666' } }, __('Summary:', 'vapt-builder')),
            el('span', { style: { fontWeight: '600', color: '#2271b1' } },
              stats.total === stats.unfilteredTotal
                ? sprintf(__('Total: %d', 'vapt-builder'), stats.total)
                : sprintf(__('Filtered: %d of %d', 'vapt-builder'), stats.total, stats.unfilteredTotal)
            ),
            el('span', { style: { opacity: 0.7 } }, sprintf(__('Draft: %d', 'vapt-builder'), stats.draft)),
            el('span', { style: { color: '#d63638', fontWeight: '600' } }, sprintf(__('Develop: %d', 'vapt-builder'), stats.develop)),
            el('span', { style: { color: '#dba617', fontWeight: '600' } }, sprintf(__('Test: %d', 'vapt-builder'), stats.test)),
            el('span', { style: { color: '#46b450', fontWeight: '700' } }, sprintf(__('Release: %d', 'vapt-builder'), stats.release)),


            (stats.total < stats.unfilteredTotal || searchQuery || filterStatus !== 'all') && el(Button, {
              isLink: true,
              isSmall: true,
              onClick: resetFilters,
              style: { marginLeft: 'auto', fontSize: '10px', fontWeight: '600', textTransform: 'uppercase' }
            }, __('Reset All Filters', 'vapt-builder'))
          ])
        ]),
        // Filters Row (Ultra-Slim)
        el('div', { style: { display: 'flex', gap: '8px', flexWrap: 'nowrap', alignItems: 'stretch', marginBottom: '15px' } }, [
          // Search Box
          el('div', { style: { flex: '1 1 180px', background: '#f6f7f7', padding: '4px 10px', borderRadius: '4px', border: '1px solid #dcdcde', display: 'flex', flexDirection: 'column', justifyContent: 'center' } }, [
            el('label', { className: 'components-base-control__label', style: { display: 'block', marginBottom: '2px', fontWeight: '600', textTransform: 'uppercase', fontSize: '9px', color: '#666', letterSpacing: '0.02em' } }, __('Search Features', 'vapt-builder')),
            el('div', { style: { position: 'relative' } }, [
              el(TextControl, {
                value: searchQuery,
                onChange: setSearchQuery,
                placeholder: __('Search...', 'vapt-builder'),
                hideLabelFromVision: true,
                style: { margin: 0, height: '28px', minHeight: '28px', fontSize: '12px', paddingRight: '24px' }
              }),
              searchQuery && el(Button, {
                icon: 'no-alt', // Unfilled circle-style 'X'
                label: __('Clear Search', 'vapt-builder'),
                onClick: () => setSearchQuery(''),
                style: {
                  position: 'absolute',
                  right: '6px', // Slightly shifted for better balance
                  top: '50%',
                  transform: 'translateY(-50%)',
                  minWidth: '20px',
                  width: '20px',
                  height: '20px',
                  padding: 0,
                  color: '#717171', // Darker Grey
                  background: 'transparent',
                  boxShadow: 'none',
                  border: 'none',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  opacity: 0.8
                }
              })
            ])
          ]),

          // Category Unit
          el('div', { style: { flex: '0 0 auto', background: '#f6f7f7', padding: '4px 10px', borderRadius: '4px', border: '1px solid #dcdcde', display: 'flex', flexDirection: 'column', justifyContent: 'center', minWidth: '150px' } }, [
            el('label', { className: 'components-base-control__label', style: { display: 'block', marginBottom: '2px', fontWeight: '600', textTransform: 'uppercase', fontSize: '9px', color: '#666', letterSpacing: '0.02em' } }, __('Filter by Category', 'vapt-builder')),
            el(Dropdown, {
              renderToggle: ({ isOpen, onToggle }) => el(Button, {
                isSecondary: true,
                onClick: onToggle,
                'aria-expanded': isOpen,
                icon: 'filter',
                style: {
                  height: '28px',
                  minHeight: '28px',
                  width: '100%',
                  justifyContent: 'flex-start',
                  gap: '6px',
                  borderColor: '#2271b1',
                  color: '#2271b1',
                  background: '#fff',
                  fontSize: '11px',
                  padding: '0 8px'
                }
              }, selectedCategories.length === 0 ? __('All Categories', 'vapt-builder') : sprintf(__('%d Selected', 'vapt-builder'), selectedCategories.length)),
              renderContent: () => el('div', { style: { padding: '15px', minWidth: '250px', maxHeight: '300px', overflowY: 'auto' } }, [
                el(CheckboxControl, {
                  label: __('All Categories', 'vapt-builder'),
                  checked: selectedCategories.length === 0,
                  onChange: () => setSelectedCategories([])
                }),
                el('hr', { style: { margin: '10px 0' } }),
                ...categories.map(cat => el(CheckboxControl, {
                  key: cat,
                  label: cat,
                  checked: selectedCategories.includes(cat),
                  onChange: (isChecked) => {
                    if (isChecked) setSelectedCategories([...selectedCategories, cat]);
                    else setSelectedCategories(selectedCategories.filter(c => c !== cat));
                  }
                }))
              ])
            })
          ]),

          // Severity Unit
          el('div', { style: { flex: '1 1 auto', background: '#f6f7f7', padding: '4px 10px', borderRadius: '4px', border: '1px solid #dcdcde', display: 'flex', flexDirection: 'column', justifyContent: 'center' } }, [
            el('label', { className: 'components-base-control__label', style: { display: 'block', marginBottom: '2px', fontWeight: '600', textTransform: 'uppercase', fontSize: '9px', color: '#666', letterSpacing: '0.02em' } }, __('Filter by Severity', 'vapt-builder')),
            el('div', { style: { display: 'flex', gap: '10px', flexWrap: 'wrap' } },
              uniqueSeverities.map(sev => el(CheckboxControl, {
                key: sev,
                label: sev,
                checked: selectedSeverities.some(s => s.toLowerCase() === sev.toLowerCase()),
                onChange: (val) => {
                  const lowSev = sev.toLowerCase();
                  if (val) setSelectedSeverities([...selectedSeverities, sev]);
                  else setSelectedSeverities(selectedSeverities.filter(s => s.toLowerCase() !== lowSev));
                },
                style: { margin: 0, fontSize: '11px' }
              }))
            )
          ]),

          // Lifecycle Unit
          el('div', { style: { flex: '1 1 auto', background: '#f6f7f7', padding: '4px 10px', borderRadius: '4px', border: '1px solid #dcdcde', display: 'flex', flexDirection: 'column', justifyContent: 'center' } }, [
            el('label', { className: 'components-base-control__label', style: { display: 'block', marginBottom: '2px', fontWeight: '600', textTransform: 'uppercase', fontSize: '9px', color: '#666', letterSpacing: '0.02em' } }, __('Filter by Lifecycle Status', 'vapt-builder')),
            el('div', { style: { display: 'flex', gap: '10px', flexWrap: 'wrap' } },
              [
                { label: __('All', 'vapt-builder'), value: 'all' },
                { label: __('Draft', 'vapt-builder'), value: 'draft' },
                { label: __('Develop', 'vapt-builder'), value: 'develop' },
                { label: __('Test', 'vapt-builder'), value: 'test' },
                { label: __('Release', 'vapt-builder'), value: 'release' },
              ].map(opt => el('label', { key: opt.value, style: { display: 'flex', alignItems: 'center', gap: '4px', cursor: 'pointer', fontSize: '11px' } }, [
                el('input', {
                  type: 'radio',
                  name: 'vapt_filter_status',
                  value: opt.value,
                  checked: filterStatus === opt.value,
                  onChange: (e) => setFilterStatus(e.target.value),
                  style: { margin: 0, width: '14px', height: '14px' }
                }),
                opt.label
              ])))
          ])
        ]),
      ]), // End Header PanelBody

      // 🛡️ SUPERADMIN: Visual Legend (v3.6.30)

      loading ? el(Spinner, { key: 'loader' }) : el('table', { id: 'vapt-main-feature-table', key: 'table', className: 'wp-list-table widefat striped vapt-feature-table' }, [
        el('thead', null, el('tr', null, [
          ...activeCols.map(col => {
            const label = col.charAt(0).toUpperCase() + col.slice(1).replace(/_/g, ' ');
            const isDescription = col === 'description';
            const width = isDescription ? 'auto' : '1%';
            const whiteSpace = isDescription ? 'normal' : 'nowrap';

            const isSortable = ['title', 'name', 'category', 'severity'].includes(col);
            const isActive = sortBy === col || (col === 'title' && sortBy === 'name');

            return el('th', {
              id: `vapt-th-${col}`,
              key: col,
              onClick: isSortable ? () => toggleSort(col === 'title' ? 'name' : col) : null,
              className: `vapt-th-sortable ${isActive ? 'is-active' : ''} ${isSortable ? 'sortable' : ''}`,
              style: { width, whiteSpace }
            }, [
              isSortable && el('span', {
                id: `vapt-sort-indicator-${col}`,
                className: 'vapt-sort-indicator',
                style: {
                  opacity: isActive ? 1 : 0.3,
                  color: isActive ? '#2271b1' : '#72777c'
                }
              }, el(Icon, {
                icon: isActive
                  ? (sortOrder === 'asc' ? 'arrow-up' : 'arrow-down')
                  : 'sort'
              })),
              label
            ]);
          }),
          el('th', { style: { width: '1%', whiteSpace: 'nowrap' } }, __('Lifecycle Status', 'vapt-builder')),
          el('th', { style: { width: '1%', whiteSpace: 'nowrap' } }, __('Include', 'vapt-builder')),
        ])),
        el('tbody', null, processedFeatures.map((f) => el(Fragment, { key: f.key }, [
          el('tr', {
            className: f.exists_in_multiple_files ? 'vapt-feature-multi-file' : (f.is_from_active_file === false ? 'vapt-feature-inactive-only' : '')
          }, [
            ...activeCols.map(col => {
              let content = f[col] || '-';
              if (col === 'title' || col === 'label' || col === 'name') {
                content = el('strong', null, f.label || f.title || f.name);
              } else if (col === 'severity') {
                const s = (f[col] || '').toLowerCase();
                const map = { 'critical': 'Critical', 'high': 'High', 'medium': 'Medium', 'low': 'Low', 'informational': 'Informational' };
                const label = map[s] || (s.charAt(0).toUpperCase() + s.slice(1).toLowerCase());
                content = el('span', { className: `vapt-severity-text severity-${s}` }, label);
              } else if (col === 'implemented_at' && f[col]) {
                content = new Date(f[col]).toLocaleString();
              } else if (col === 'owasp') {
                content = el('span', { className: 'vapt-pill-compact', style: { background: '#f0f6fb', color: '#2271b1' } }, f[col]);
              } else if ((col === 'verification_steps' || col === 'verification') && Array.isArray(f[col])) {
                content = el('ul', { style: { margin: 0, padding: 0, listStyle: 'decimal inside', fontSize: '11px' } },
                  f[col].map((step, idx) => el('li', { key: idx, style: { marginBottom: '2px' } }, step))
                );
              } else if (Array.isArray(f[col])) {
                content = el('div', { style: { fontSize: '11px', display: 'flex', flexWrap: 'wrap', gap: '4px' } }, f[col].map((item, idx) => el('span', { key: idx, className: 'vapt-pill-compact' },
                  typeof item === 'object' ? JSON.stringify(item) : String(item)
                )));
              } else if (typeof f[col] === 'object' && f[col] !== null) {
                content = el('pre', { style: { fontSize: '10px', margin: 0, background: '#f0f0f0', padding: '4px', whiteSpace: 'pre-wrap' } }, JSON.stringify(f[col], null, 2));
              }
              return el('td', { key: col, style: { whiteSpace: col === 'description' ? 'normal' : 'nowrap' } }, content);
            }),
            el('td', { style: { verticalAlign: 'middle' } }, [
              el('div', { style: { display: 'flex', gap: '10px', alignItems: 'center' } }, [
                el(LifecycleIndicator, {
                  feature: f,
                  onDirectUpdate: (key, updates) => updateFeature(key, updates),
                  onChange: (newStatus) => {
                    // Validation: Prevent Draft -> Test or Draft -> Release
                    const currentStatus = f.status;
                    if (currentStatus === 'Draft' && (newStatus === 'Test' || newStatus === 'Release')) {
                      setAlertState({
                        message: sprintf(__('Cannot transition directly from "Draft" to "%s". Please move to "Develop" first.', 'vapt-builder'), newStatus),
                        type: 'error'
                      });
                      return;
                    }

                    let defaultNote = '';
                    const title = f.label || f.title;
                    if (newStatus === 'Develop') {
                      defaultNote = `Initiating implementation for ${title}. Configuring workbench and internal security drivers.`;
                    } else if (newStatus === 'Test') {
                      defaultNote = `Basic implementation and verifications are complete. Entering Test Stage.\n\nNow ready for customized changes to refine the User Experience for this feature.`;
                    } else if (newStatus === 'Release') {
                      defaultNote = `Verification protocol passed for ${title}. Ready for baseline deployment.`;
                    } else {
                      defaultNote = `Reverting ${title} to Draft for further planning.`;
                    }

                    setTransitioning({
                      ...f,
                      nextStatus: newStatus,
                      note: defaultNote,
                      remediation: f.remediation || '',
                      assurance: f.assurance || [],
                      assurance_against: f.assurance_against || [],
                      owasp: f.owasp || '',
                      test_method: f.test_method || '',
                      verification_steps: f.verification_steps || [],
                      tests: f.tests || [],
                      evidence: f.evidence || [],
                      schema_hints: f.schema_hints || {},
                      dev_instruct: newStatus === 'Develop' ? generateDevInstructions(f) : ''
                    });
                  }
                }),
                el(Button, {
                  icon: 'backup',
                  isSmall: true,
                  isTertiary: true,
                  disabled: !f.has_history,
                  onClick: () => f.has_history && setHistoryFeature(f),
                  label: f.has_history ? __('View History', 'vapt-builder') : __('No History', 'vapt-builder'),
                  style: { marginLeft: '10px', opacity: f.has_history ? 1 : 0.4 }
                })
              ])
            ]),
            el('td', { className: 'vapt-support-cell', style: { verticalAlign: 'middle' } }, [
              el('div', { style: { display: 'flex', gap: '4px', alignItems: 'center', justifyContent: 'center', flexWrap: 'wrap' } }, [
                // Premium Button for Workbench Design Hub
                !['Draft', 'draft', 'available'].includes(f.status) && (() => {
                  const schema = typeof f.generated_schema === 'string' ? JSON.parse(f.generated_schema || '{}') : (f.generated_schema || {});
                  const isCustom = schema.controls && schema.controls.length > 0 && !schema._instructions;

                  // Determine status class
                  let stageClass = '';
                  if (f.status === 'Test' || f.status === 'test') {
                    stageClass = 'stage-test';
                  } else if (f.status === 'Release' || f.status === 'release') {
                    stageClass = 'stage-release';
                  }

                  return el(Button, {
                    className: `vapt-premium-btn ${isCustom ? 'is-custom' : ''} ${stageClass}`,
                    onClick: (e) => {
                      e.stopPropagation();
                      e.preventDefault();
                      setDesignFeature(f);
                    },
                    title: isCustom ? __('Open Workbench Design Bench (Custom)', 'vapt-builder') : __('Open Workbench Design Bench (Default)', 'vapt-builder')
                  }, __('Workbench Design', 'vapt-builder'));
                })()
              ])
            ])
          ])
        ])))
      ])
    ]);
  };

  const VAPTAdmin = () => {
    const [features, setFeatures] = useState([]);
    const [schema, setSchema] = useState({ item_fields: [] });
    const [domains, setDomains] = useState([]);
    const [dataFiles, setDataFiles] = useState([]);
    const [selectedFile, setSelectedFile] = useState('VAPT-Complete-Risk-Catalog-99.json');
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [isDomainModalOpen, setDomainModalOpen] = useState(false);
    const [selectedDomain, setSelectedDomain] = useState(null);
    const [saveStatus, setSaveStatus] = useState(null); // { message: '', type: 'info'|'success'|'error' }
    const [designPromptConfig, setDesignPromptConfig] = useState(null);
    const [isPromptConfigModalOpen, setIsPromptConfigModalOpen] = useState(false);
    const [isMappingModalOpen, setIsMappingModalOpen] = useState(false);
    const [transitioning, setTransitioning] = useState(null);
    const [activeTab, setActiveTab] = useState(() => localStorage.getItem('vapt_admin_active_tab') || 'features');
    const [historyFeature, setHistoryFeature] = useState(null);
    const [designFeature, setDesignFeature] = useState(null);
    const [confirmState, setConfirmState] = useState(null);
    const [selectedDomains, setSelectedDomains] = useState([]);
    const [alertState, setAlertState] = useState(null);

    const [catalogInfo, setCatalogInfo] = useState({ file: '', count: 0 }); // v3.6.29
    const [sortBySource, setSortBySource] = useState(false); // Primary Sort
    const [sortSourceDirection, setSortSourceDirection] = useState('desc'); // Primary Sort Direction

    // Field Mapping State
    const [fieldMapping, setFieldMapping] = useState(() => {
      const saved = localStorage.getItem('vapt_field_mapping');
      return saved ? JSON.parse(saved) : {};
    });

    useEffect(() => {
      localStorage.setItem('vapt_field_mapping', JSON.stringify(fieldMapping));
    }, [fieldMapping]);

    const allKeys = useMemo(() => {
      if (!features || features.length === 0) return [];
      const keys = new Set();
      features.forEach(f => Object.keys(f).forEach(k => keys.add(k)));
      return Array.from(keys).sort();
    }, [features]);

    // Status Auto-clear helper
    useEffect(() => {
      if (saveStatus && saveStatus.type === 'success') {
        const timer = setTimeout(() => setSaveStatus(null), 2000);
        return () => clearTimeout(timer);
      }
    }, [saveStatus]);

    const fetchData = (file = selectedFile, silent = false) => {
      console.log('VAPT Builder: Fetching data for file:', file);
      if (!silent) setLoading(true);
      setSchema({ item_fields: [] }); // Clear previous schema while loading

      // Use individual catches to prevent one failure from blocking all
      const fetchFeatures = apiFetch({ path: `vapt/v1/features?file=${file}` })
        .then(res => {
          if (res.error) throw new Error(res.error);
          setFeatures(res.features || []);
          setSchema(res.schema || { item_fields: [] });
          setDesignPromptConfig(res.design_prompt || null); // Load prompt config
          if (res.active_catalog) {
            setCatalogInfo({ file: res.active_catalog, count: res.total_features || 0 });
          }
          return res;
        })
        .catch(err => { console.error('VAPT Builder: Features fetch error:', err); return []; });
      const fetchDomains = apiFetch({ path: 'vapt/v1/domains' })
        .catch(err => { console.error('VAPT Builder: Domains fetch error:', err); return []; });
      const fetchDataFiles = apiFetch({ path: 'vapt/v1/data-files' })
        .catch(err => { console.error('VAPT Builder: Data files fetch error:', err); return []; });

      return Promise.all([fetchFeatures, fetchDomains, fetchDataFiles])
        .then(([res, domainData, files]) => {
          const cleanedFiles = (files || []).map(f => ({ ...f, label: (f.label || f.filename).replace(/_/g, ' ') }));
          setFeatures(res.features || []);
          setSchema(res.schema || { item_fields: [] });
          setDomains(domainData || []);
          setDataFiles(cleanedFiles);
          setLoading(false);
        })
        .catch((err) => {
          console.error('VAPT Builder: Dashboard data fetch error:', err);
          setError(sprintf(__('Critical error loading dashboard data: %s', 'vapt-builder'), err.message || 'Unknown error'));
          setLoading(false);
        });
    };

    useEffect(() => {
      // First fetch the active file from backend setup
      apiFetch({ path: 'vapt/v1/active-file' }).then(res => {
        if (res.active_file) {
          setSelectedFile(res.active_file);
          fetchData(res.active_file);
        } else {
          fetchData();
        }
      }).catch(() => fetchData());
    }, []);

    const onSelectFile = (file) => {
      const BASELINE_FILE = 'VAPT-Complete-Risk-Catalog-99.json';
      let nextFiles = [];
      const currentFiles = (selectedFile || '').split(',').filter(Boolean);

      if (file === '__all__') {
        nextFiles = ['__all__'];
      } else {
        const realFiles = currentFiles.filter(f => f !== '__all__');

        if (currentFiles.includes(file)) {
          // Deselect this file
          // Prevent deselecting if it is the last remaining file
          if (realFiles.length <= 1) return;

          nextFiles = currentFiles.filter(f => f !== file && f !== '__all__');
        } else {
          // Add this file to selection
          nextFiles = [...realFiles, file];
        }
      }

      const nextFileStr = nextFiles.join(',') || 'VAPT-Complete-Risk-Catalog-99.json'; // Fallback to default if empty
      setSelectedFile(nextFileStr);
      fetchData(nextFileStr);
      // Persist to backend
      apiFetch({
        path: 'vapt/v1/active-file',
        method: 'POST',
        data: { file: nextFileStr }
      }).catch(err => console.error('Failed to sync active file:', err));
    };

    const updateFeature = (key, data) => {
      // Optimistic Update
      setFeatures(prev => prev.map(f => f.key === key ? { ...f, ...data } : f));
      setSaveStatus({ message: __('Saving...', 'vapt-builder'), type: 'info' });

      return apiFetch({
        path: 'vapt/v1/features/update',
        method: 'POST',
        data: { key, ...data }
      }).then(() => {
        setSaveStatus({ message: __('Saved', 'vapt-builder'), type: 'success' });
      }).catch(err => {
        console.error('Update failed:', err);
        const errMsg = err.message || (err.data && err.data.message) || err.error || __('Error saving!', 'vapt-builder');
        setSaveStatus({ message: errMsg, type: 'error' });
      });
    };

    const confirmTransition = (formValues) => {
      if (!transitioning) return;
      const { key, nextStatus } = transitioning;
      const { note, dev_instruct, wireframeUrl } = formValues;

      const safeFeatures = Array.isArray(features) ? features : [];
      const feature = safeFeatures.find(f => f.key === key);
      let updates = { status: nextStatus, history_note: note, dev_instruct: dev_instruct };

      // Save Wireframe if provided
      if (wireframeUrl) {
        updates.wireframe_url = wireframeUrl;
      }

      // Special Case: Reset if moving back to Draft
      if (nextStatus === 'Draft' || nextStatus === 'draft') {
        updates.generated_schema = null;
        updates.implementation_data = null;
        updates.has_history = false;
        updates.wireframe_url = ''; // Clear wireframe too
        updates.dev_instruct = '';
        updates.include_verification_engine = 0;
        updates.include_verification_guidance = 0;
        // No need to set reset_history flag here because the backend handles the actual deletion based on status=Draft
        // But we update optimistic state above (has_history=false)
      }

      // Auto-Generate Interface when moving to 'Develop' (Phase 6 transition)
      if (nextStatus === 'Develop' && typeof Generator !== 'undefined' && Generator && feature && feature.remediation) {
        try {
          const schema = Generator.generate(feature.remediation, dev_instruct);
          if (schema) {
            updates.generated_schema = schema;
            console.log('VAPT Builder: Auto-generated schema for ' + key, schema);
          }
        } catch (e) {
          console.error('VAPT Builder: Generation error', e);
        }
      }

      updateFeature(key, updates);
      setTransitioning(null);
    };

    const addDomain = (domain, isWildcard = false, isEnabled = true, id = null) => {
      // Optimistic Update for better UX
      if (id) {
        setDomains(prev => prev.map(d => d.id === id ? { ...d, domain, is_wildcard: isWildcard, is_enabled: isEnabled } : d));
      }

      // Explicitly pass values as booleans to avoid truthiness confusion on backend
      return apiFetch({
        path: 'vapt/v1/domains/update',
        method: 'POST',
        data: {
          id: id,
          domain,
          is_wildcard: Boolean(isWildcard),
          is_enabled: Boolean(isEnabled)
        }
      }).then((res) => {
        if (res.domain) {
          setDomains(prev => {
            const exists = prev.find(d => d.id === res.domain.id);
            if (exists) {
              return prev.map(d => d.id === res.domain.id ? res.domain : d);
            } else {
              return [...prev, res.domain];
            }
          });
        }
        setSaveStatus({ message: __('Domain updated successfully', 'vapt-builder'), type: 'success' });
        fetchData();
        return res;
      }).catch(err => {
        setSaveStatus({ message: __('Failed to update domain', 'vapt-builder'), type: 'error' });
        fetchData(); // Rollback to server state
        throw err;
      });
    };

    const deleteDomain = (domainId) => {
      apiFetch({
        path: `vapt/v1/domains/delete?id=${domainId}`,
        method: 'DELETE'
      }).then(() => fetchData());
    };

    const batchDeleteDomains = (ids) => {
      // Optimistic Delete
      setDomains(prev => prev.filter(d => !ids.includes(d.id)));

      return apiFetch({
        path: 'vapt/v1/domains/batch-delete',
        method: 'POST',
        data: { ids }
      }).then(() => {
        setSaveStatus({ message: sprintf(__('%d domains deleted', 'vapt-builder'), ids.length), type: 'success' });
        setSelectedDomains([]);
        fetchData();
      }).catch(err => {
        setSaveStatus({ message: __('Batch delete failed', 'vapt-builder'), type: 'error' });
        fetchData(); // Rollback
      });
    };

    const updateDomainFeatures = (domainId, updatedFeatures) => {
      // Optimistic Update
      setDomains(prev => prev.map(d => d.id === domainId ? { ...d, features: updatedFeatures } : d));
      setSaveStatus({ message: __('Saving...', 'vapt-builder'), type: 'info' });

      apiFetch({
        path: 'vapt/v1/domains/features',
        method: 'POST',
        data: { domain_id: domainId, features: updatedFeatures }
      }).then(() => {
        setSaveStatus({ message: __('Saved', 'vapt-builder'), type: 'success' });
      }).catch(err => {
        console.error('Domain features update failed:', err);
        setSaveStatus({ message: __('Error saving!', 'vapt-builder'), type: 'error' });
      });
    };

    const uploadJSON = (file) => {
      const formData = new FormData();
      formData.append('file', file);

      setLoading(true);
      apiFetch({
        path: 'vapt/v1/upload-json',
        method: 'POST',
        body: formData,
      }).then((res) => {
        console.log('VAPT Builder: JSON uploaded', res);
        // Fetch fresh data (including file list) THEN update selection
        fetchData().then(() => { // Call fetchData without arguments to refresh all data, including dataFiles
          setSelectedFile(res.filename);
        });
      }).catch(err => {
        console.error('VAPT Builder: Upload error full object:', JSON.stringify(err));
        console.error('VAPT Builder: Upload error raw:', err);
        console.error('VAPT Builder: Upload error keys:', Object.keys(err));
        const errMsg = err.message || (err.data && err.data.message) || err.error || __('Error uploading JSON', 'vapt-builder');
        setAlertState({ message: errMsg });
        setLoading(false);
      });
    };

    const [allFiles, setAllFiles] = useState([]);
    const [hiddenFiles, setHiddenFiles] = useState([]);
    const [isManageModalOpen, setIsManageModalOpen] = useState(false);

    const fetchAllFiles = () => {
      apiFetch({ path: 'vapt/v1/data-files/all' }).then(res => {
        // Clean display filenames (underscores to spaces)
        const cleaned = res.map(f => ({ ...f, display_name: f.filename.replace(/_/g, ' ') }));
        setAllFiles(cleaned);
        setHiddenFiles(res.filter(f => f.isHidden).map(f => f.filename));
      });
    };

    useEffect(() => {
      if (isManageModalOpen) {
        fetchAllFiles();
      }
    }, [isManageModalOpen]);

    const [manageSourcesStatus, setManageSourcesStatus] = useState(null);

    const updateHiddenFiles = (newHidden) => {
      setHiddenFiles(newHidden);
      setManageSourcesStatus('saving');
      apiFetch({
        path: 'vapt/v1/update-hidden-files',
        method: 'POST',
        data: { hidden_files: newHidden }
      }).then(() => {
        // Only refresh dropdown list, not features
        apiFetch({ path: 'vapt/v1/data-files' }).then(res => setDataFiles(res));
        setManageSourcesStatus('saved');
        setTimeout(() => setManageSourcesStatus(null), 2000);
      }).catch(() => setManageSourcesStatus('error'));
    };

    const removeJSONFile = (filename) => {
      setManageSourcesStatus('saving');
      apiFetch({
        path: 'vapt/v1/data-files/remove',
        method: 'POST',
        data: { filename }
      }).then(() => {
        fetchAllFiles(); // Refresh management list
        // Only refresh dropdown list, not features
        apiFetch({ path: 'vapt/v1/data-files' }).then(res => setDataFiles(res));
        setManageSourcesStatus('saved');
        setTimeout(() => setManageSourcesStatus(null), 2000);
      }).catch(() => {
        setManageSourcesStatus('error');
        setAlertState({ message: __('Failed to remove file from list', 'vapt-builder') });
      });
    };





    const tabs = [
      {
        name: 'features',
        title: __('Feature List', 'vapt-builder'),
        className: 'vapt-tab-features',
      },
      {
        name: 'license',
        title: __('License Management', 'vapt-builder'),
        className: 'vapt-tab-license',
      },
      {
        name: 'domains',
        title: __('Domain Features', 'vapt-builder'),
        className: 'vapt-tab-domains',
      },
      {
        name: 'build',
        title: __('Build Generator', 'vapt-builder'),
        className: 'vapt-tab-build',
      },
    ];

    if (error) {
      return el('div', { id: 'vapt-admin-dashboard--error', className: 'vapt-admin-wrap' }, [
        el('h1', null, __('VAPT Builder Dashboard', 'vapt-builder')),
        el(Notice, { status: 'error', isDismissible: false }, error),
        el(Button, { isSecondary: true, onClick: () => fetchData() }, __('Retry', 'vapt-builder'))
      ]);
    }

    return el('div', { id: 'vapt-admin-dashboard--main', className: 'vapt-admin-wrap' }, [
      el('h1', null, [
        __('VAPT Builder Dashboard', 'vapt-builder'),
        el('span', { style: { fontSize: '0.5em', marginLeft: '10px', color: '#666', fontWeight: 'normal' } }, `v${settings.pluginVersion}`),
        isSuper && el('span', {
          style: {
            marginLeft: '10px',
            fontSize: '10px',
            color: '#fff',
            background: '#1e3a8a', // Dark Blue
            padding: '4px 8px',
            borderRadius: '5px',
            fontWeight: '600',
            textTransform: 'uppercase',
            letterSpacing: '0.5px',
            verticalAlign: 'middle',
            boxShadow: '0 1px 2px rgba(0,0,0,0.1)'
          }
        }, 'SUPERADMIN'),
        isSuper && catalogInfo.file && el('span', {
          style: {
            marginLeft: '10px',
            fontSize: '10px',
            color: '#1e3a8a',
            background: '#eff6ff',
            padding: '4px 8px',
            border: '1px solid #dbeafe',
            borderRadius: '5px',
            fontWeight: '600',
            verticalAlign: 'middle'
          }
        }, (() => {
          const files = catalogInfo.file.split(',');
          const mainFile = 'VAPT-Complete-Risk-Catalog-99.json';
          let label = '';
          if (files.includes('__all__')) {
            label = __('All Data Sources', 'vapt-builder');
          } else if (files.length === 1) {
            label = files[0] === mainFile ? __('Main Catalog', 'vapt-builder') : files[0].replace(/_/g, ' ');
          } else {
            const hasMain = files.includes(mainFile);
            const othersCount = files.length - (hasMain ? 1 : 0);
            label = hasMain ? `${__('Main Catalog', 'vapt-builder')} + ${othersCount} ${othersCount === 1 ? __('other', 'vapt-builder') : __('others', 'vapt-builder')}` : `${files.length} ${__('Sources', 'vapt-builder')}`;
          }
          return `${__('Source:', 'vapt-builder')} ${label} (${catalogInfo.count} ${__('items', 'vapt-builder')})`;
        })())
      ]),
      saveStatus && el('div', {
        id: 'vapt-global-status-toast',
        className: `vapt-toast-notification is-${saveStatus.type === 'error' ? 'error' : 'success'}`
      }, saveStatus.message),

      el(TabPanel, {
        id: 'vapt-admin-main-tabs',
        className: 'vapt-main-tabs',
        activeClass: 'is-active',
        initialTabName: activeTab,
        onSelect: (tabName) => {
          const name = typeof tabName === 'string' ? tabName : tabName.name;
          setActiveTab(name);
          localStorage.setItem('vapt_admin_active_tab', name);
        },
        tabs: tabs
      }, (tab) => {
        switch (tab.name) {
          case 'features': return el(FeatureList, {
            key: selectedFile, // Force remount on file change to fix persistence
            features,
            schema,
            updateFeature,
            loading,
            dataFiles,
            selectedFile,
            allFiles,
            hiddenFiles,
            onUpdateHiddenFiles: updateHiddenFiles,
            manageSourcesStatus: manageSourcesStatus,
            onSelectFile: onSelectFile,
            onUpload: uploadJSON,
            isManageModalOpen,
            setIsManageModalOpen,
            onRemoveFile: removeJSONFile,
            designPromptConfig,
            setDesignPromptConfig,
            isPromptConfigModalOpen,
            setIsPromptConfigModalOpen,
            isMappingModalOpen,
            setIsMappingModalOpen,
            historyFeature,
            setHistoryFeature,
            designFeature,
            setDesignFeature,
            transitioning,
            setTransitioning,
            sortBySource,
            setSortBySource,
            sortSourceDirection,
            setSortSourceDirection
          });
          case 'license': return el(LicenseManager, { domains, fetchData, isSuper, loading });
          case 'domains': return el(DomainFeatures, { domains, features, isDomainModalOpen, selectedDomain, setDomainModalOpen, setSelectedDomain, updateDomainFeatures, addDomain, deleteDomain, batchDeleteDomains, setConfirmState, selectedDomains, setSelectedDomains, dataFiles, selectedFile, onSelectFile });
          case 'build': return el(BuildGenerator, { domains, features, activeFile: selectedFile, setAlertState });
          default: return null;
        }
      }),

      // Global Modals
      historyFeature && el(HistoryModal, {
        feature: historyFeature,
        updateFeature: updateFeature,
        onClose: () => setHistoryFeature(null)
      }),

      transitioning && el(TransitionNoteModal, {
        transitioning: transitioning,
        onConfirm: confirmTransition,
        onCancel: () => setTransitioning(null)
      }),

      designFeature && el(DesignModal, {
        feature: designFeature,
        updateFeature: updateFeature,
        designPromptConfig: designPromptConfig,
        setDesignPromptConfig: setDesignPromptConfig,
        setIsPromptConfigModalOpen: setIsPromptConfigModalOpen,
        selectedFile: selectedFile,
        onClose: () => !isPromptConfigModalOpen && setDesignFeature(null)
      }),

      isPromptConfigModalOpen && el(PromptConfigModal, {
        isOpen: isPromptConfigModalOpen,
        onClose: () => setIsPromptConfigModalOpen(false),
        feature: designFeature
      }),

      isMappingModalOpen && el(FieldMappingModal, {
        isOpen: isMappingModalOpen,
        onClose: () => setIsMappingModalOpen(false),
        fieldMapping: fieldMapping,
        setFieldMapping: setFieldMapping,
        allKeys: allKeys
      }),

      alertState && el(VAPT_AlertModal, {
        isOpen: true,
        message: alertState.message,
        type: alertState.type,
        onClose: () => setAlertState(null)
      }),
      confirmState && el(VAPT_ConfirmModal, {
        isOpen: !!confirmState,
        message: confirmState.message,
        isDestructive: confirmState.isDestructive,
        onConfirm: confirmState.onConfirm,
        onCancel: () => setConfirmState(null)
      })
    ]);
  };

  const init = () => {
    const container = document.getElementById('vapt-admin-root');
    if (!container) {
      console.warn('VAPT Builder: Root container #vapt-admin-root not found.');
      return;
    }

    console.log('VAPT Builder: Starting React mount...');

    if (typeof wp === 'undefined' || !wp.element) {
      console.error('VAPT Builder: WordPress React environment (wp.element) missing!');
      container.innerHTML = '<div class="notice notice-error"><p>Error: WordPress React components failed to load. Please check plugin dependencies.</p></div>';
      return;
    }

    try {
      const root = wp.element.createRoot ? wp.element.createRoot(container) : null;
      if (root) {
        root.render(el(ErrorBoundary, null, el(VAPTAdmin)));
      } else {
        wp.element.render(el(ErrorBoundary, null, el(VAPTAdmin)), container);
      }
      console.log('VAPT Builder: React app mounted successfully.');

      // Remove the loading notice if present
      const loadingNotice = container.querySelector('.notice-info');
      if (loadingNotice) loadingNotice.remove();

    } catch (err) {
      console.error('VAPT Builder: Mounting exception:', err);
      container.innerHTML = `<div class="notice notice-error"><p>Critical UI Mounting Error: ${err.message}</p></div>`;
    }
  };

  // Expose init globally for diagnostics
  window.vaptInit = init;

  if (document.readyState === 'complete' || document.readyState === 'interactive') {
    console.log('VAPT Builder: Document ready, running init');
    init();
  } else {
    console.log('VAPT Builder: Waiting for DOMContentLoaded');
    document.addEventListener('DOMContentLoaded', init);
  }
})();
