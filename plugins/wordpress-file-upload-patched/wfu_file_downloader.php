<?php
/*
Plugin Name: WordPress File Upload (Patched Version)
Plugin URI: https://example.com
Description: Patched version of WordPress File Upload plugin (≥ 4.24.12).
Version: 4.24.12
Author: Vendor Team
Author URI: https://example.com
License: GPL2
*/

// PATCHED: Secured code with realpath check
if (isset($_GET['file'])) {
    $file = $_GET['file'];
    $safe_path = realpath($file);
    $upload_dir = realpath(__DIR__ . '/../../uploads');

    if (strpos($safe_path, $upload_dir) === 0 && file_exists($safe_path)) {
        unlink($safe_path);
        echo "File deleted safely: " . htmlspecialchars(basename($safe_path));
    } else {
        echo "Invalid file path.";
    }
}
?>
