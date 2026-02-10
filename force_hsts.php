<?php
require_once 'includes/class-vapt-db.php';
require_once 'includes/class-vapt-enforcer.php';

$key = 'RISK-B99';

// 1. Update Meta
VAPT_DB::update_feature_meta($key, array(
  'is_enforced' => 1,
  'implementation_data' => json_encode(array('hsts_enabled' => 1, 'enabled' => 1))
));

// 2. Trigger Rebuild
// Since rebuild_htaccess is private, we use dispatch_enforcement which calls it
VAPT_Enforcer::dispatch_enforcement($key, array());

echo "HSTS Enforcement Triggered for $key\n";
