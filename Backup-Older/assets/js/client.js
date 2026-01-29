// Client Dashboard Entry Point
// Phase 6 Implementation - IDE Workbench Redesign
(function () {
  console.log('VAPT Builder: client.js loaded');
  if (typeof wp === 'undefined') return;

  const { render, useState, useEffect, useMemo, Fragment, createElement: el } = wp.element || {};
  const { Button, ToggleControl, Spinner, Notice, Card, CardBody, CardHeader, CardFooter, Icon, Tooltip, Modal } = wp.components || {};
  const apiFetch = wp.apiFetch;
  const { __, sprintf } = wp.i18n || {};

  const settings = window.vaptSettings || window.vaptSettings || {};
  const isSuper = settings.isSuper || false;
  const GeneratedInterface = window.VAPT_GeneratedInterface || window.vapt_GeneratedInterface;

  const STATUS_LABELS = {
    'Develop': __('Develop', 'vapt-builder'),
    'Test': __('Test', 'vapt-builder'),
    'Release': __('Release', 'vapt-builder')
  };

  const ClientDashboard = () => {
    const [features, setFeatures] = useState([]);
    const [loading, setLoading] = useState(true);
    const [isRefreshing, setIsRefreshing] = useState(false);
    const [error, setError] = useState(null);
    const [activeStatus, setActiveStatus] = useState(() => {
      const saved = localStorage.getItem('vapt_workbench_active_status');
      return saved ? saved : 'Develop';
    });
    const [activeCategory, setActiveCategory] = useState('all');
    const [saveStatus, setSaveStatus] = useState(null);
    const [verifFeature, setVerifFeature] = useState(null);

    useEffect(() => {
      localStorage.setItem('vapt_workbench_active_status', activeStatus);
    }, [activeStatus]);

    // Auto-dismiss Success Toasts
    useEffect(() => {
      if (saveStatus && saveStatus.type === 'success') {
        const timer = setTimeout(() => setSaveStatus(null), 1500);
        return () => clearTimeout(timer);
      }
    }, [saveStatus]);

    const fetchData = (refresh = false) => {
      if (refresh) setIsRefreshing(true);
      else setLoading(true);

      const domain = settings.currentDomain || window.location.hostname;
      apiFetch({ path: `vapt/v1/features?scope=client&domain=${domain}` })
        .then(data => {
          setFeatures(data.features || []);
          setLoading(false);
          setIsRefreshing(false);
        })
        .catch(err => {
          setError(err.message || 'Failed to load features');
          setLoading(false);
          setIsRefreshing(false);
        });
    };

    useEffect(() => {
      fetchData();
    }, []);

    const updateFeature = (key, data) => {
      setFeatures(prev => prev.map(f => f.key === key ? { ...f, ...data } : f));
      setSaveStatus({ message: __('Saving...', 'vapt-builder'), type: 'info' });

      apiFetch({
        path: 'vapt/v1/features/update',
        method: 'POST',
        data: { key, ...data }
      })
        .then(() => setSaveStatus({ message: __('Saved', 'vapt-builder'), type: 'success' }))
        .catch(err => {
          console.error('Save failed:', err);
          setSaveStatus({ message: __('Save Failed', 'vapt-builder'), type: 'error' });
        });
    };

    const availableStatuses = useMemo(() => isSuper ? ['Develop', 'Test', 'Release'] : ['Release'], [isSuper]);

    const statusFeatures = useMemo(() => {
      return features.filter(f => {
        const s = f.normalized_status || (f.status ? f.status.toLowerCase() : '');
        const active = activeStatus.toLowerCase();
        if (active === 'develop') return ['develop', 'in_progress'].includes(s);
        if (active === 'test') return ['test', 'testing'].includes(s);
        if (active === 'release') return ['release', 'implemented'].includes(s);
        return s === active;
      });
    }, [features, activeStatus]);

    const categories = useMemo(() => {
      const cats = [...new Set(statusFeatures.map(f => f.category || 'Uncategorized'))].sort();
      return cats;
    }, [statusFeatures]);

    useEffect(() => {
      if (categories.length > 0) {
        if (!activeCategory || (activeCategory !== 'all' && !categories.includes(activeCategory))) {
          setActiveCategory('all');
        }
      } else {
        setActiveCategory(null);
      }
    }, [categories]);

    const displayFeatures = useMemo(() => {
      if (!activeCategory) return [];
      if (activeCategory === 'all') return statusFeatures;
      return statusFeatures.filter(f => (f.category || 'Uncategorized') === activeCategory);
    }, [statusFeatures, activeCategory]);

    const scrollToFeature = (featureKey, category) => {
      if (activeCategory !== 'all' && activeCategory !== category) {
        setActiveCategory(category);
        setTimeout(() => {
          const el = document.getElementById(`feature-${featureKey}`);
          if (el) el.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }, 150);
      } else {
        const el = document.getElementById(`feature-${featureKey}`);
        if (el) el.scrollIntoView({ behavior: 'smooth', block: 'center' });
      }
    };

    // Helper to render a single feature card
    const renderFeatureCard = (f, setVerifFeature) => {
      const schema = typeof f.generated_schema === 'string' ? JSON.parse(f.generated_schema) : (f.generated_schema || { controls: [] });
      const isVerifEngine = f.include_verification_engine;

      // Filter controls
      // 1. Implementation Controls (Left Column)
      const implControls = schema.controls ? schema.controls.filter(c =>
        !['test_action', 'risk_indicators', 'assurance_badges', 'test_checklist', 'evidence_list'].includes(c.type) &&
        !c.label?.toLowerCase().includes('notes')
      ) : [];

      // 2. Automated Controls (Right Column)
      const automControls = schema.controls ? schema.controls.filter(c => c.type === 'test_action') : [];
      const noteControls = schema.controls ? schema.controls.filter(c => c.label?.toLowerCase().includes('notes')) : [];

      return el(Card, { key: f.key, id: `feature-${f.key}`, style: { borderRadius: '12px', border: '1px solid #e5e7eb', boxShadow: 'none' } }, [
        el(CardHeader, { style: { borderBottom: '1px solid #f3f4f6', padding: '12px 24px' } }, [
          el('div', { style: { display: 'grid', gridTemplateColumns: '1fr auto', alignItems: 'center', gap: '20px', width: '100%' } }, [
            el('div', null, [
              el('div', { style: { display: 'flex', alignItems: 'center', gap: '8px' } }, [
                el('h3', { style: { margin: 0, fontSize: '16px', fontWeight: 700, color: '#111827' } }, f.label),
                f.description && el(Tooltip, { text: f.description },
                  el(Icon, { icon: 'info-outline', size: 16, style: { color: '#94a3b8', cursor: 'help' } })
                )
              ])
            ]),
            el('div', { style: { display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: '10px' } }, [
              el('span', { className: `vapt-status-badge status-${f.status.toLowerCase()}`, style: { fontSize: '10px', fontWeight: 700, padding: '2px 8px', borderRadius: '4px', textTransform: 'uppercase' } }, f.status),
              el('div', { style: { display: 'flex', alignItems: 'center', background: '#f8fafc', padding: '6px 12px', borderRadius: '8px', border: '1px solid #e2e8f0' } }, [
                el('span', { style: { fontSize: '12px', fontWeight: 600, color: '#334155', marginRight: '12px', whiteSpace: 'nowrap' } }, __('Enforce Rule')),
                el(ToggleControl, {
                  checked: !!f.is_enforced,
                  onChange: (val) => updateFeature(f.key, { is_enforced: val }),
                  __nextHasNoMarginBottom: true,
                  style: { margin: 0 }
                })
              ])
            ])
          ])
        ]),
        el(CardBody, { style: { padding: '24px' } }, [
          el('div', { style: { display: 'grid', gridTemplateColumns: 'minmax(0, 1.3fr) minmax(0, 0.7fr)', gap: '25px', alignItems: 'stretch' } }, [
            // Left Column: Implementation
            el('div', { className: 'vapt-implementation-panel', style: { padding: '20px', background: '#fff', borderRadius: '8px', border: '1px solid #e2e8f0', boxShadow: '0 1px 2px rgba(0,0,0,0.05)', display: 'flex', flexDirection: 'column' } }, [
              el('h4', { style: { margin: '0 0 20px 0', fontSize: '14px', fontWeight: 700, color: '#111827', display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid #f1f5f9', paddingBottom: '10px' } }, [
                el('span', { style: { display: 'flex', alignItems: 'center', gap: '8px' } }, [
                  el(Icon, { icon: 'admin-settings', size: 18 }),
                  __('Functional Implementation', 'vapt-builder')
                ])
              ]),
              el('div', { style: { flex: 1 } }, [
                f.generated_schema && GeneratedInterface
                  ? el(GeneratedInterface, { feature: { ...f, generated_schema: { ...schema, controls: implControls } }, onUpdate: (data) => updateFeature(f.key, { implementation_data: data }) })
                  : el('div', { style: { padding: '30px', background: '#f9fafb', border: '1px dashed #d1d5db', borderRadius: '8px', textAlign: 'center', color: '#9ca3af', fontSize: '13px' } },
                    __('No configurable controls.', 'vapt-builder'))
              ]),

              el('div', { style: { marginTop: '25px', paddingTop: '15px', borderTop: '1px solid #f1f5f9' } }, [
                el(Button, {
                  isSecondary: true,
                  onClick: () => setVerifFeature(f),
                  icon: 'shield',
                  style: { borderRadius: '6px', width: '100%', justifyContent: 'center' }
                }, __('Open Manual Verification Protocol', 'vapt-builder'))
              ])
            ]),

            // Right Column: Automated Verification
            el('div', { className: 'vapt-automation-panel', style: { display: 'flex', flexDirection: 'column', gap: '15px', height: '100%' } }, [
              // Automated Engine
              el('div', { style: { padding: '15px', background: '#f8fafc', borderRadius: '8px', border: '1px solid #e2e8f0', flex: 1, display: 'flex', flexDirection: 'column' } }, [
                el('h4', { style: { margin: '0 0 15px 0', fontSize: '12px', fontWeight: 700, color: '#0f766e', textTransform: 'uppercase', letterSpacing: '0.05em', display: 'flex', alignItems: 'center', gap: '6px' } }, [
                  el(Icon, { icon: 'yes-alt', size: 16 }),
                  __('Automated Verification Engine', 'vapt-builder')
                ]),
                el('div', { style: { flex: 1 } }, [
                  automControls.length > 0 ? el(GeneratedInterface, {
                    feature: { ...f, generated_schema: { ...schema, controls: automControls } },
                    onUpdate: (data) => updateFeature(f.key, { implementation_data: data })
                  }) : el('p', { style: { fontSize: '12px', color: '#64748b', fontStyle: 'italic', margin: 0 } }, __('No automated tests defined.', 'vapt-builder'))
                ])
              ])
            ])
          ]),

          // Operational Notes (Full Width, Below Grid)
          noteControls.length > 0 && el('div', { style: { marginTop: '25px', padding: '15px', background: '#fff', borderRadius: '8px', border: '1px solid #e2e8f0' } }, [
            el('h4', { style: { margin: '0 0 10px 0', fontSize: '12px', fontWeight: 700, color: '#475569', textTransform: 'uppercase', display: 'flex', alignItems: 'center', gap: '8px' } }, [
              el(Icon, { icon: 'editor-help', size: 18 }),
              __('Operational Notes', 'vapt-builder')
            ]),
            el(GeneratedInterface, {
              feature: { ...f, generated_schema: { ...schema, controls: noteControls } },
              onUpdate: (data) => updateFeature(f.key, { implementation_data: data })
            })
          ])
        ]),
        el(CardFooter, { style: { borderTop: '1px solid #f3f4f6', padding: '12px 24px', background: '#fafafa' } }, [
          el('span', { style: { fontSize: '11px', color: '#9ca3af' } }, sprintf(__('Feature Reference: %s', 'vapt-builder'), f.key))
        ])
      ]);
    };

    if (loading) return el('div', { className: 'vapt-loading' }, [el(Spinner), el('p', null, __('Loading Workbench...', 'vapt-builder'))]);
    if (error) return el(Notice, { status: 'error', isDismissible: false }, error);

    return el('div', { className: 'vapt-workbench-root', style: { display: 'flex', flexDirection: 'column', minHeight: 'calc(100vh - 120px)', background: '#f9fafb', position: 'relative', paddingBottom: '40px' } }, [

      // Toast Notification
      saveStatus && el('div', {
        style: {
          position: 'absolute', top: '20px', left: '50%', transform: 'translateX(-50%)',
          background: saveStatus.type === 'error' ? '#fde8e8' : (saveStatus.type === 'success' ? '#def7ec' : '#e0f2fe'),
          color: saveStatus.type === 'error' ? '#9b1c1c' : (saveStatus.type === 'success' ? '#03543f' : '#0369a1'),
          padding: '8px 16px', borderRadius: '20px', boxShadow: '0 4px 6px rgba(0,0,0,0.1)',
          zIndex: 9999, fontWeight: '600', fontSize: '12px', display: 'flex', alignItems: 'center', gap: '8px',
          border: '1px solid rgba(0,0,0,0.05)'
        }
      }, [
        el(Icon, { icon: saveStatus.type === 'error' ? 'warning' : (saveStatus.type === 'success' ? 'yes' : 'update'), size: 16 }),
        saveStatus.message
      ]),

      // Top Navigation
      el('header', { style: { padding: '15px 30px', background: '#fff', borderBottom: '1px solid #e5e7eb', display: 'flex', justifyContent: 'space-between', alignItems: 'center' } }, [
        el('div', { style: { display: 'flex', alignItems: 'center', gap: '15px' } }, [
          el('h2', { style: { margin: 0, fontSize: '18px', fontWeight: 700, color: '#111827', display: 'flex', alignItems: 'baseline', gap: '8px' } }, [
            __('VAPT Implementation Dashboard'),
            el('span', { style: { fontSize: '11px', color: '#9ca3af', fontWeight: '400' } }, `v${settings.pluginVersion}`)
          ]),
          el('span', { style: { fontSize: '10px', background: '#dcfce7', color: '#166534', padding: '1px 6px', borderRadius: '4px', textTransform: 'uppercase', letterSpacing: '0.05em' } }, isSuper ? __('Superadmin') : __('Standard')),
          el(Button, {
            icon: 'update',
            isSmall: true,
            isSecondary: true,
            onClick: () => fetchData(true),
            disabled: loading || isRefreshing,
            isBusy: isRefreshing,
            label: __('Refresh Data', 'vapt-builder')
          })
        ]),
        el('div', { style: { display: 'flex', gap: '5px', background: '#f3f4f6', padding: '4px', borderRadius: '8px' } },
          availableStatuses.map(s => el(Button, {
            key: s,
            onClick: () => setActiveStatus(s),
            style: {
              background: activeStatus === s ? '#fff' : 'transparent',
              color: activeStatus === s ? '#111827' : '#6b7280',
              border: 'none', borderRadius: '6px', padding: '8px 16px', fontWeight: 600, fontSize: '13px',
              boxShadow: activeStatus === s ? '0 1px 3px rgba(0,0,0,0.1)' : 'none'
            }
          }, STATUS_LABELS[s]))
        )
      ]),

      // Main Content Area
      el('div', { style: { display: 'flex', flexGrow: 1, overflow: 'visible' } }, [
        // Sidebar
        el('aside', { className: 'vapt-workbench-sidebar', style: { width: '280px', borderRight: '1px solid #e5e7eb', background: '#fff', overflowY: 'auto', overflowX: 'visible', padding: '20px 0' } }, [
          el('div', { style: { padding: '0 20px 10px', fontSize: '11px', fontWeight: 700, color: '#9ca3af', textTransform: 'uppercase' } }, __('Feature Categories')),
          categories.length > 0 && el(Fragment, null, [
            el('button', {
              onClick: () => setActiveCategory('all'),
              className: 'vapt-sidebar-link' + (activeCategory === 'all' ? ' is-active' : ''),
              style: {
                width: '100%', border: 'none', background: activeCategory === 'all' ? '#eff6ff' : 'transparent',
                color: activeCategory === 'all' ? '#1d4ed8' : '#4b5563',
                padding: '12px 20px', textAlign: 'left', cursor: 'pointer', display: 'flex', justifyContent: 'space-between',
                borderRight: activeCategory === 'all' ? '3px solid #1d4ed8' : 'none', fontWeight: activeCategory === 'all' ? 600 : 500,
                fontSize: '14px'
              }
            }, [
              el('span', null, __('All Categories', 'vapt-builder')),
              el('span', { style: { fontSize: '11px', background: activeCategory === 'all' ? '#dbeafe' : '#f3f4f6', padding: '2px 6px', borderRadius: '4px' } }, statusFeatures.length)
            ]),
            activeCategory === 'all' && el('div', {
              style: {
                display: 'flex', flexDirection: 'column', gap: '2px',
                padding: '5px 0', background: '#fcfcfd', borderBottom: '1px solid #e5e7eb'
              }
            }, statusFeatures.map(f => el('a', {
              key: f.key,
              onClick: (e) => { e.preventDefault(); scrollToFeature(f.key, 'all'); },
              className: 'vapt-workbench-link',
              href: `#feature-${f.key}`,
              style: {
                fontSize: '13px', color: '#64748b', cursor: 'pointer', whiteSpace: 'nowrap',
                overflow: 'hidden', textOverflow: 'ellipsis', padding: '8px 20px',
                transition: 'all 0.2s ease', position: 'relative', zIndex: 10,
                display: 'block', textDecoration: 'none'
              },
              title: f.label
            }, f.label)))
          ]),
          categories.length === 0 && el('p', { style: { padding: '20px', color: '#9ca3af', fontSize: '13px' } }, __('No active categories', 'vapt-builder')),
          categories.map(cat => {
            const catFeatures = statusFeatures.filter(f => (f.category || 'Uncategorized') === cat);
            const isActive = activeCategory === cat;
            return el(Fragment, { key: cat }, [
              el('button', {
                onClick: () => setActiveCategory(cat),
                className: 'vapt-sidebar-link' + (isActive ? ' is-active' : ''),
                style: {
                  width: '100%', border: 'none', background: isActive ? '#eff6ff' : 'transparent',
                  color: isActive ? '#1d4ed8' : '#4b5563',
                  padding: '12px 20px', textAlign: 'left', cursor: 'pointer', display: 'flex', justifyContent: 'space-between',
                  borderRight: isActive ? '3px solid #1d4ed8' : 'none', fontWeight: isActive ? 600 : 500,
                  fontSize: '14px', position: 'relative'
                }
              }, [
                el('span', null, cat),
                el('span', { style: { fontSize: '11px', background: isActive ? '#dbeafe' : '#f3f4f6', padding: '2px 6px', borderRadius: '4px' } }, catFeatures.length)
              ]),
              isActive && el('div', {
                style: {
                  display: 'flex', flexDirection: 'column', gap: '2px',
                  padding: '5px 0', background: '#fcfcfd', borderBottom: '1px solid #e5e7eb'
                }
              }, catFeatures.map(f => el('a', {
                key: f.key,
                onClick: (e) => { e.preventDefault(); scrollToFeature(f.key, cat); },
                className: 'vapt-workbench-link',
                href: `#feature-${f.key}`,
                style: {
                  fontSize: '13px', color: '#64748b', cursor: 'pointer', whiteSpace: 'nowrap',
                  overflow: 'hidden', textOverflow: 'ellipsis', padding: '8px 20px',
                  transition: 'all 0.2s ease', position: 'relative', zIndex: 10,
                  display: 'block', textDecoration: 'none'
                },
                title: f.label
              }, f.label)))
            ]);
          })
        ]),

        // Workspace
        el('main', { style: { flexGrow: 1, padding: '30px', overflowY: 'auto' } }, [
          displayFeatures.length === 0 ? el('div', { style: { textAlign: 'center', padding: '100px', color: '#9ca3af' } }, __('Select a category to view implementation controls.', 'vapt-builder')) :
            el('div', { style: { maxWidth: '1000px', margin: '0 auto', display: 'flex', flexDirection: 'column', gap: '30px' } },
              activeCategory === 'all'
                ? categories.map(cat => {
                  const catFeats = statusFeatures.filter(f => (f.category || 'Uncategorized') === cat);
                  return el('section', { key: cat, style: { marginBottom: '20px' } }, [
                    el('h4', { style: { borderBottom: '2px solid #e5e7eb', paddingBottom: '10px', marginBottom: '25px', color: '#374151', fontSize: '14px', textTransform: 'uppercase', letterSpacing: '0.05em' } }, cat),
                    el('div', { style: { display: 'flex', flexDirection: 'column', gap: '20px' } },
                      catFeats.map(f => renderFeatureCard(f, setVerifFeature))
                    )
                  ]);
                })
                : displayFeatures.map(f => renderFeatureCard(f, setVerifFeature))
            )
        ])
      ]),

      // Functional Verification Modal (Simplified)
      verifFeature && el(Modal, {
        title: sprintf(__('Manual Verification: %s', 'vapt-builder'), verifFeature.label),
        onRequestClose: () => setVerifFeature(null),
        style: { width: '700px', maxWidth: '98%' }
      }, (() => {
        const f = verifFeature;
        const schema = typeof f.generated_schema === 'string' ? JSON.parse(f.generated_schema) : (f.generated_schema || { controls: [] });

        // Extracted Manual Steps Only
        const protocol = f.test_method || '';
        const checklist = typeof f.verification_steps === 'string' ? JSON.parse(f.verification_steps) : (f.verification_steps || []);
        const guideItems = schema.controls ? schema.controls.filter(c => ['test_checklist', 'evidence_list'].includes(c.type)) : [];
        const support = schema.controls ? schema.controls.filter(c => ['risk_indicators', 'assurance_badges'].includes(c.type)) : [];

        const boxStyle = { padding: '15px', background: '#fff', borderRadius: '8px', border: '1px solid #e2e8f0', boxShadow: '0 1px 2px rgba(0,0,0,0.05)' };

        return el('div', { style: { display: 'flex', flexDirection: 'column', gap: '20px', padding: '10px' } }, [
          // Manual Protocol & Evidence
          (protocol || checklist.length > 0 || guideItems.length > 0) ? el('div', { style: { ...boxStyle, background: '#f8fafc' } }, [
            el('h4', { style: { margin: '0 0 15px 0', fontSize: '12px', fontWeight: 700, color: '#475569', textTransform: 'uppercase', letterSpacing: '0.05em' } }, __('Manual Verification Protocol', 'vapt-builder')),

            protocol && el('div', { style: { marginBottom: '20px' } }, [
              el('label', { style: { display: 'block', fontSize: '11px', fontWeight: 700, color: '#92400e', marginBottom: '8px', textTransform: 'uppercase' } }, __('Test Protocol')),
              el('ol', { style: { margin: 0, paddingLeft: '20px', fontSize: '12px', color: '#4b5563', lineHeight: '1.6' } },
                protocol.split('\n').filter(l => l.trim()).map((l, i) => el('li', { key: i, style: { marginBottom: '4px' } }, l.replace(/^\d+\.\s*/, '')))
              )
            ]),

            checklist.length > 0 && el('div', { style: { marginBottom: '20px' } }, [
              el('label', { style: { display: 'block', fontSize: '11px', fontWeight: 700, color: '#0369a1', marginBottom: '8px', textTransform: 'uppercase' } }, __('Evidence Checklist')),
              el('ol', { style: { margin: 0, padding: 0, listStyle: 'none' } },
                checklist.map((step, i) => el('li', { key: i, style: { fontSize: '12px', color: '#4b5563', display: 'flex', gap: '10px', alignItems: 'flex-start', marginBottom: '8px' } }, [
                  el('input', { type: 'checkbox', style: { margin: '3px 0 0 0', width: '14px', height: '14px' } }),
                  el('span', null, step)
                ]))
              )
            ]),

            guideItems.length > 0 && el(GeneratedInterface, {
              feature: { ...f, generated_schema: { ...schema, controls: guideItems } },
              onUpdate: (data) => updateFeature(f.key, { implementation_data: data }),
              isGuidePanel: true
            })
          ]) : el('div', { style: { padding: '20px', textAlign: 'center', color: '#9ca3af', fontStyle: 'italic' } }, __('No manual verification steps defined.', 'vapt-builder')),

          // Assurance Badges
          support.length > 0 && el('div', { style: { ...boxStyle, background: '#f0fdf4', border: '1px solid #bbf7d0' } }, [
            el('h4', { style: { margin: '0 0 12px 0', fontSize: '12px', fontWeight: 700, color: '#166534', textTransform: 'uppercase', letterSpacing: '0.05em' } }, __('Verification & Assurance')),
            el(GeneratedInterface, { feature: { ...f, generated_schema: { ...schema, controls: support } }, onUpdate: (data) => updateFeature(f.key, { implementation_data: data }) })
          ])
        ]);
      })())
    ]);
  };

  const init = () => {
    const container = document.getElementById('vapt-client-root');
    if (container) render(el(ClientDashboard), container);
  };
  if (document.readyState === 'complete') init(); else document.addEventListener('DOMContentLoaded', init);
})();
