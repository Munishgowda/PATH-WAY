<?php
/*
Plugin Name: WordPress File Upload (Test Vulnerable Version)
Plugin URI: https://example.com
Description: Vulnerable plugin for educational use only (CVE-2024-9047).
Version: 4.24.11
Author: Research Team
Author URI: https://example.com
License: GPL2
*/

// WARNING: Vulnerable code for educational use only
if (isset($_GET['file'])) {
    $file = $_GET['file'];
    if (file_exists($file)) {
        unlink($file); // Dangerous deletion without validation
        echo "File deleted: " . htmlspecialchars($file);
    } else {
        echo "File not found.";
    }
}
?>
