<?php
$filePath = 'assets/js/admin.js';
$content = file_get_contents($filePath);

$pattern = "/onSubmit: \(e\) => e\.preventDefault\(\),, className: 'vapt-design-modal-inner-layout' \}, \[/m";
$replacement = "onSubmit: (e) => e.preventDefault(), \n        className: 'vapt-design-modal-inner-layout' \n      }, [";

if (preg_match($pattern, $content)) {
  $newContent = preg_replace($pattern, $replacement, $content);
  if (file_put_contents($filePath, $newContent)) {
    echo "SUCCESS: Trimmed onSubmit line in admin.js.";
  } else {
    echo "ERROR: Failed to write to admin.js.";
  }
} else {
  echo "ERROR: Could not find malformed line in admin.js.";
}
