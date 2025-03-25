=== Custom Logs ===
Contributors: byronjacobs
Tags: debug, logs, logging, wordpress debug, admin tools
Requires at least: 4.8
Tested up to: 6.7
Stable tag: 1.0
Requires PHP: 7.4
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

A sleek, modern plugin to manage WordPress debug logs with custom directories, levels, and advanced AJAX filtering.

== Description ==

Custom Logs is a powerful and user-friendly plugin designed to help WordPress developers and administrators manage debug logs efficiently. With a modern interface, it offers complete control over custom and WP_DEBUG logs, including custom directories, log levels, and real-time AJAX filtering.

### Key Features
- **Custom Log Management**: Define custom log file names and directories within the uploads folder.
- **WP_DEBUG Integration**: Capture and redirect WP_DEBUG logs to a custom file.
- **Log Levels**: Filter logs by severity (None, All, Errors, Warnings, Notices).
- **AJAX-Powered Log Viewer**: Dynamically filter log entries by file and type without page reloads.
- **Backup and Clear Logs**: Easily back up or clear logs with a single click.
- **Download Logs**: Download custom or WP_DEBUG logs directly from the admin panel.
- **Sleek UI**: A modern, responsive design with uniform input heights for a polished experience.

This is the initial release (v1.0), providing a robust foundation for log management with advanced features like AJAX filtering built-in from the start.

== Installation ==

1. Upload the `custom-logs` folder to the `/wp-content/plugins/` directory.
2. Activate the plugin through the 'Plugins' menu in WordPress.
3. Navigate to the 'Custom Logs' menu in the WordPress admin dashboard to configure settings.

== Usage ==

1. **Enable Logging**: Turn on custom logging and set a log level under "Custom Logging".
2. **Set Log Files**: Specify custom log file names and directories under "General" and "WP Debug Logging".
3. **View Logs**: Use the Log Viewer to select a log file and filter by type (e.g., Errors, Info) with real-time AJAX updates.
4. **Manage Logs**: Test, clear, back up, or delete logs from the "Management" section.
5. **Download Logs**: Use the "Downloads" section to save logs locally.

To log custom messages, use the `custom_logs()` function in your code:
```php
custom_logs("This is a test message", "info");