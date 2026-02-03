<?php
// Standalone DB Access
define('DB_NAME', 'local');
define('DB_USER', 'root');
define('DB_PASSWORD', 'root');
define('DB_HOST', 'localhost');

$conn = new mysqli(DB_HOST, DB_USER, DB_PASSWORD, DB_NAME);
if ($conn->connect_error) {
  die("Connection failed: " . $conn->connect_error);
}

$key = '11';
$table = 'wp_vapt_feature_meta';
$result = $conn->query("SELECT * FROM $table WHERE feature_key = '$key'");

if ($result->num_rows > 0) {
  while ($row = $result->fetch_assoc()) {
    echo "KEY: " . $row["feature_key"] . "\n";
    echo "IS_ENFORCED: " . $row["is_enforced"] . "\n";
    echo "SCHEMA:\n" . $row["generated_schema"] . "\n";
    echo "IMPL DATA:\n" . $row["implementation_data"] . "\n";
  }
} else {
  echo "0 results for key $key";
}
$conn->close();
