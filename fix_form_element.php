<?php
$filePath = 'assets/js/admin.js';
$content = file_get_contents($filePath);

// Pattern to find the el('div', { id: 'vapt-design-modal-form', ...
$pattern = "/el\('div',\s+\{\s+id:\s+'vapt-design-modal-form'/m";
$replacement = "el('form', { \n        id: 'vapt-design-modal-form', \n        onSubmit: (e) => e.preventDefault(),";

if (preg_match($pattern, $content)) {
  $newContent = preg_replace($pattern, $replacement, $content);
  if (file_put_contents($filePath, $newContent)) {
    echo "SUCCESS: Converted vapt-design-modal-form to form with onSubmit.";
  } else {
    echo "ERROR: Failed to write to admin.js.";
  }
} else {
  echo "ERROR: Could not find target div with ID: vapt-design-modal-form";
}
