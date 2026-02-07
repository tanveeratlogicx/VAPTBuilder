<?php
$adminJs = 'assets/js/admin.js';
$phpFile = 'vapt-builder.php';
$pkgFile = 'package.json';

// 1. Update admin.js guidance block visibility
$content = file_get_contents($adminJs);
$search = "if (!displayInstruct) return null;";
$replace = "// Always show if we have something or a placeholder\n            if (!displayInstruct) {\n              displayInstruct = __('No specific development guidance available for this feature transition.', 'vapt-builder');\n            }";

if (strpos($content, $search) !== false) {
  $newContent = str_replace($search, $replace, $content);
  file_put_contents($adminJs, $newContent);
  echo "SUCCESS: Updated admin.js guidance visibility.\n";
} else {
  echo "ERROR: Could not find guidance visibility check in admin.js.\n";
}

// 2. Bump version to 3.6.8
$phpContent = file_get_contents($phpFile);
$phpContent = str_replace('3.6.7', '3.6.8', $phpContent);
file_put_contents($phpFile, $phpContent);
echo "SUCCESS: Bumped version in vapt-builder.php.\n";

$pkgContent = file_get_contents($pkgFile);
$pkgContent = str_replace('3.6.7', '3.6.8', $pkgContent);
file_put_contents($pkgFile, $pkgContent);
echo "SUCCESS: Bumped version in package.json.\n";
