<?php
/*
Plugin Name: WordPress File Upload (Manually Hardened)
Plugin URI: https://example.com
Description: Hardened version of WordPress File Upload with extra path validation, whitelisting, and logging.
Version: 4.24.12+hardening
Author: Your Name (MSc Research)
License: GPL2
*/

// --- Manually Hardened Path Deletion Handler ---
if (isset($_GET['file'])) {
    $file = $_GET['file'];
    
    // Block common traversal patterns
    if (strpos($file, '..') !== false || strpos($file, '/') !== false || strpos($file, '\\') !== false) {
        echo "Blocked: Suspicious path detected.";
        exit;
    }

    // Enforce allowed extensions
    $allowed_extensions = ['txt', 'jpg', 'png'];
    $extension = pathinfo($file, PATHINFO_EXTENSION);
    if (!in_array(strtolower($extension), $allowed_extensions)) {
        echo "Blocked: File extension not allowed.";
        exit;
    }

    // Whitelist filenames
    $whitelist = ['dummy.txt', 'test.jpg'];  // You define these
    if (!in_array($file, $whitelist)) {
        echo "Blocked: File not in whitelist.";
        exit;
    }

    // Get full path
    $upload_dir = realpath(__DIR__ . '/../../uploads');
    $target_file = realpath($upload_dir . '/' . $file);

    // Final safety check: must stay within uploads directory
    if ($target_file && strpos($target_file, $upload_dir) === 0 && file_exists($target_file)) {
        unlink($target_file);
        echo "✅ Hardened: File deleted - " . htmlspecialchars(basename($target_file));

        // Optional: Log deletion
        file_put_contents(__DIR__ . '/deletion_log.txt', date('Y-m-d H:i:s') . " - Deleted: " . basename($target_file) . PHP_EOL, FILE_APPEND);
    } else {
        echo "❌ Error: File does not exist or outside allowed directory.";
    }
} else {
    echo "No file specified.";
}
?>
