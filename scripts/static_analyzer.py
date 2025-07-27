import os
import re

def scan_php_file(file_path):
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    issues = []
    
    # Rule 1: Detect unlink() with direct user input
    if re.search(r"unlink\s*\(\s*\$_(GET|POST|REQUEST)\s*\[", content):
        issues.append("⚠️ Possible insecure file deletion with unlink() and user input")

    # Rule 2: Detect file_get_contents() with direct user input
    if re.search(r"file_get_contents\s*\(\s*\$_(GET|POST|REQUEST)\s*\[", content):
        issues.append("⚠️ Possible insecure file read with file_get_contents() and user input")

    # Rule 3: General unlink usage (indirect)
    if re.search(r"unlink\s*\(", content):
        if "realpath(" in content:
            issues.append("ℹ️ unlink() found – realpath() also found, likely safe")
        else:
            issues.append("⚠️ unlink() found – cannot confirm if safe")


    # Rule 4: Check for presence of validation functions
    if "realpath(" not in content and "basename(" not in content:
        issues.append("⚠️ No path validation functions (realpath, basename) used")

    return issues


def analyze_plugin(plugin_dir):
    if not os.path.exists(plugin_dir):
        print(f"❌ Directory not found: {plugin_dir}")
        return

    has_issues = False
    for root, dirs, files in os.walk(plugin_dir):
        for file in files:
            if file.endswith('.php'):
                full_path = os.path.join(root, file)
                issues = scan_php_file(full_path)
                if issues:
                    has_issues = True
                    print(f"\n📄 File: {full_path}")
                    for issue in issues:
                        print(issue)

    if not has_issues:
        print("✅ No issues found in this plugin.")

# List of plugin directories to scan
plugin_paths = [
    ("Vulnerable Plugin", r"plugins\wordpress-file-upload-vuln"),
    ("Patched Plugin", r"plugins\wordpress-file-upload-patched"),
    ("Hardened Plugin",r"plugins\wordpress-file-upload-hardened")
]

# Main execution
if __name__ == "__main__":
    for label, path in plugin_paths:
        print(f"\n🧪 Scanning {label}:")
        analyze_plugin(path)
