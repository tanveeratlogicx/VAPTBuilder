<?php
$adminJs = 'assets/js/admin.js';
$phpFile = 'vapt-builder.php';
$pkgFile = 'package.json';

// 1. Update admin.js guidance block visibility with Regex
$content = file_get_contents($adminJs);
$pattern = '/if\s*\(!displayInstruct\)\s*return\s*null;/';
$replace = "// Always show if we have something or a placeholder\n            if (!displayInstruct) {\n              displayInstruct = __('No specific development guidance available for this feature transition.', 'vapt-builder');\n            }";

if (preg_match($pattern, $content)) {
  $newContent = preg_replace($pattern, $replace, $content);
  file_put_contents($adminJs, $newContent);
  echo "SUCCESS: Regex matched and replaced guidance visibility.\n";
} else {
  echo "ERROR: Regex did NOT match in admin.js.\n";
  // Debug: output a snippet around where we expect it
  if (preg_match('/displayInstruct/', $content, $m, PREG_OFFSET_CAPTURE)) {
    echo "Found 'displayInstruct' at offset " . $m[0][1] . "\n";
  }
}

// 2. Bump version to 3.6.8 (ensuring we replace the current version)
function bumpVersion($file, $old, $new)
{
  if (file_exists($file)) {
    $c = file_get_contents($file);
    if (strpos($c, $old) !== false) {
      $nc = str_replace($old, $new, $c);
      file_put_contents($file, $nc);
      echo "SUCCESS: Bumped $file from $old to $new.\n";
    } else {
      echo "WARNING: Could not find version $old in $file.\n";
    }
  } else {
    echo "ERROR: File $file does not exist.\n";
  }
}

bumpVersion($phpFile, '3.6.7', '3.6.8');
bumpVersion($pkgFile, '3.6.7', '3.6.8');
