<?php
/*
 * Plugin Name:       Custom Logs
 * Plugin URI:        https://heavyweightdigital.co.za
 * Description:       A sleek, modern plugin to manage WordPress debug logs with custom directories, levels, and advanced filtering.
 * Version:           1.0
 * Requires at least: 4.8
 * Requires PHP:      7.4
 * Author:            Byron Jacobs
 * Author URI:        https://heavyweightdigital.co.za
 * License:           GPL v2 or later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       custom-logs
 */

if (!defined('ABSPATH')) {
    exit;
}


class CL_Config_Transformer
{
    private $config_file;

    public function __construct()
    {
        $this->config_file = ABSPATH . 'wp-config.php';
    }

    public function exists($type, $name)
    {
        if (!is_readable($this->config_file)) {
            return false;
        }
        $content = file_get_contents($this->config_file);
        return strpos($content, "define('$name'") !== false || strpos($content, "define(\"$name\"") !== false;
    }

    public function get_value($type, $name)
    {
        if (!is_readable($this->config_file)) {
            return null;
        }
        $content = file_get_contents($this->config_file);
        if ($content === false) {
            return null;
        }
        $name = preg_quote($name, '/');
        $pattern = "/define\s*\(\s*['\"]" . preg_quote($name, '/') . "['\"]\s*,\s*(.*?)\s*\);/";
        $result = preg_match($pattern, $content, $matches);
        return $result && isset($matches[1]) ? trim($matches[1], "'\"") : null;
    }

    public function update($type, $name, $value, $options = [])
    {
        if (!is_writable($this->config_file)) {
            return;
        }
        $content = file_get_contents($this->config_file);
        $raw = isset($options['raw']) && $options['raw'];
        $value_str = $raw ? $value : "'$value'";
        if ($this->exists($type, $name)) {
            $pattern = "/define\s*\(\s*['\"]" . preg_quote($name, '/') . "['\"]\s*,\s*(.*?)\s*\);/";
            $content = preg_replace($pattern, "define('$name', $value_str);", $content);
        } else {
            $content = preg_replace("/<\?php/", "<?php\ndefine('$name', $value_str);", $content, 1);
        }
        file_put_contents($this->config_file, $content);
    }

    public function remove($type, $name)
    {
        if (!is_writable($this->config_file)) {
            return;
        }
        $content = file_get_contents($this->config_file);
        $pattern = "/define\s*\(\s*['\"]" . preg_quote($name, '/') . "['\"]\s*,\s*(.*?)\s*\);/";
        $content = preg_replace($pattern, "", $content);
        file_put_contents($this->config_file, $content);
    }
}

register_activation_hook(__FILE__, 'custom_logs_create_initial_logs');

function custom_logs_create_initial_logs()
{
    global $wp_filesystem;
    if (!WP_Filesystem()) {
        return false;
    }

    $upload = wp_upload_dir();
    $log_dir_name = 'custom-logs';
    $log_dir = $upload['basedir'] . '/' . $log_dir_name . '/';
    $wp_debug_dir = $log_dir . 'wp_debug/';
    $custom_debug_dir = $log_dir . 'custom_debug/';

    if (!$wp_filesystem->exists($log_dir)) {
        $wp_filesystem->mkdir($log_dir);
    }
    if (!$wp_filesystem->exists($wp_debug_dir)) {
        $wp_filesystem->mkdir($wp_debug_dir);
    }
    if (!$wp_filesystem->exists($custom_debug_dir)) {
        $wp_filesystem->mkdir($custom_debug_dir);
    }

    $custom_log_file = $custom_debug_dir . 'debug.log';
    $wp_debug_log_file = $wp_debug_dir . 'wp-debug.log';

    $timestamp = gmdate('Y-m-d H:i:s');
    if (!$wp_filesystem->exists($custom_log_file)) {
        $wp_filesystem->put_contents($custom_log_file, "[$timestamp] [INFO]: Custom log file created.\n");
    }
    if (!$wp_filesystem->exists($wp_debug_log_file)) {
        $wp_filesystem->put_contents($wp_debug_log_file, "[$timestamp] [INFO]: WP debug log file created.\n");
    }

    update_option('logging_enabled', false);
    update_option('log_level', 'none');
    update_option('capture_wp_debug_logs', false);
    update_option('log_dir_name', $log_dir_name);
    update_option('custom_logs_file_path', $custom_log_file);
    update_option('wp_debug_log_file_path', $wp_debug_log_file);
}

function custom_logs_error_handler($errno, $errstr, $errfile, $errline)
{
    if (!(error_reporting() & $errno)) {
        return false;
    }

    $type = '';
    switch ($errno) {
        case E_ERROR:
        case E_USER_ERROR:
            $type = 'PHP Fatal';
            break;
        case E_WARNING:
        case E_USER_WARNING:
            $type = 'PHP Warning';
            break;
        case E_NOTICE:
        case E_USER_NOTICE:
            $type = 'PHP Notice';
            break;
        case E_DEPRECATED:
        case E_USER_DEPRECATED:
            $type = 'PHP Deprecated';
            break;
        case E_PARSE:
            $type = 'PHP Parse';
            break;
        default:
            $type = 'Other';
            break;
    }

    $message = "$errstr in $errfile on line $errline";
    $filtered_message = apply_filters('log_error', $message, $type, $errfile);

    if ($filtered_message !== false) {
        error_log("[$type] $filtered_message");
    }

    return false; // Let PHP handle the error as well if needed
}

// Set custom error handler
set_error_handler('custom_logs_error_handler');

function custom_logs_capture_wp_debug_logs()
{
    $capture_enabled = get_option('capture_wp_debug_logs', false);
    if (!$capture_enabled) {
        return;
    }

    $wp_debug_level = get_option('wp_debug_level', 'all');
    $upload = wp_upload_dir();
    $log_dir_name = get_option('log_dir_name', 'custom-logs');
    $log_dir = $upload['basedir'] . '/' . $log_dir_name . '/';
    $wp_debug_dir = $log_dir . 'wp_debug/';
    $wp_debug_log_file = get_option('wp_debug_log_file_path', $wp_debug_dir . 'wp-debug.log');

    $wp_config = new CL_Config_Transformer();

    if ($wp_config->exists('constant', 'WP_DEBUG_LOG')) {
        $existing_log = $wp_config->get_value('constant', 'WP_DEBUG_LOG');
        if ($existing_log && $existing_log !== 'true' && $existing_log !== 'false' && $existing_log !== $wp_debug_log_file) {
            if (is_file($existing_log)) {
                $content = file_get_contents($existing_log);
                file_put_contents($wp_debug_log_file, $content);
                unlink($existing_log);
            }
        }
    }

    $options = ['add' => true, 'raw' => true, 'normalize' => false];
    $wp_config->update('constant', 'WP_DEBUG', 'true', $options);
    $wp_config->update('constant', 'SCRIPT_DEBUG', 'true', $options);
    $wp_config->update('constant', 'WP_DEBUG_LOG', $wp_debug_log_file, ['add' => true, 'raw' => false]);
    $wp_config->update('constant', 'WP_DEBUG_DISPLAY', 'false', $options);

    // Add custom error logging filter
    add_filter('log_error', 'custom_logs_filter_wp_debug', 10, 3);
}

function custom_logs_filter_wp_debug($message, $type, $file)
{
    $wp_debug_level = get_option('wp_debug_level', 'all');
    $allowed_types = [
        'all' => ['PHP Fatal', 'PHP Warning', 'PHP Notice', 'PHP Deprecated', 'PHP Parse', 'PHP Exception', 'Database', 'Other'],
        'PHP Fatal' => ['PHP Fatal'],
        'PHP Warning' => ['PHP Warning'],
        'PHP Notice' => ['PHP Notice'],
        'PHP Deprecated' => ['PHP Deprecated'],
        'PHP Parse' => ['PHP Parse'],
        'PHP Exception' => ['PHP Exception'],
        'Database' => ['Database'],
        'Other' => ['Other']
    ];

    if (!isset($allowed_types[$wp_debug_level])) {
        return $message; // Default to logging everything if level is invalid
    }

    if (in_array($type, $allowed_types[$wp_debug_level])) {
        return $message; // Log the message if type matches the debug level
    }

    return false; // Suppress the message if type doesn't match
}

add_action('muplugins_loaded', 'custom_logs_capture_wp_debug_logs', -100);

add_action('admin_menu', 'log_file_menu');
function log_file_menu()
{
    add_menu_page(
        esc_html__('Custom Logs', 'custom-logs'),
        esc_html__('Custom Logs', 'custom-logs'),
        'manage_options',
        'custom-log-file',
        'log_file_page',
        'dashicons-media-text'
    );
}

add_action('admin_enqueue_scripts', 'custom_logs_enqueue_assets');
function custom_logs_enqueue_assets($hook)
{
    if ($hook !== 'toplevel_page_custom-log-file') {
        return;
    }
    wp_enqueue_style('custom-logs-style', plugin_dir_url(__FILE__) . 'assets/css/custom-logs.css', [], '1.0');
    wp_enqueue_script('custom-logs-script', plugin_dir_url(__FILE__) . 'assets/js/custom-logs.js', ['jquery'], '1.0', true);
    wp_localize_script('custom-logs-script', 'customLogsAjax', [
        'ajax_url' => admin_url('admin-ajax.php'),
        'nonce' => wp_create_nonce('custom_logs_filter_nonce')
    ]);
}

/**
 * Processes log file entries into a structured array, supporting both custom and WordPress debug log formats
 */
function custom_logs_process_entries($log_file, $page = 1, $per_page = 100)
{
    global $wp_filesystem;
    if (!WP_Filesystem() || !$wp_filesystem->exists($log_file)) {
        return [];
    }

    $log = $wp_filesystem->get_contents($log_file);
    $lines = explode("\n", $log);
    $errors_master_list = [];

    foreach ($lines as $line) {
        if (empty(trim($line))) {
            continue;
        }

        // Pattern for custom log format: [<timestamp>] [<type>]: <details>
        $custom_pattern = "/\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]\s*\[([A-Z]+)\]:\s*(.+)/";
        // Pattern for WordPress debug log format: [<timestamp>] PHP <type>: <details>
        $wp_pattern = "/\[(\d{2}-[A-Za-z]{3}-\d{4} \d{2}:\d{2}:\d{2} [A-Z]+)\]\s*(PHP\s+[A-Za-z\s]+):\s*(.+)/";

        if (preg_match($custom_pattern, $line, $custom_matches)) {
            $timestamp = $custom_matches[1];
            $type = $custom_matches[2];
            $details = $custom_matches[3];
        } elseif (preg_match($wp_pattern, $line, $wp_matches)) {
            $timestamp = $wp_matches[1];
            $type = trim($wp_matches[2]); // e.g., "PHP Notice", "PHP Warning"
            $details = $wp_matches[3];
        } else {
            continue; // Skip lines that don't match either format
        }

        // Add each entry as unique, no deduplication by details
        $errors_master_list[] = [
            'type' => $type,
            'details' => trim($details),
            'occurrences' => [$timestamp]
        ];
    }

    // Sort entries by timestamp (newest first)
    usort($errors_master_list, function ($a, $b) {
        $a_time = strtotime($a['occurrences'][0]);
        $b_time = strtotime($b['occurrences'][0]);
        return $b_time - $a_time; // Descending order
    });

    // Paginate the results
    $total_entries = count($errors_master_list);
    $offset = ($page - 1) * $per_page;
    $paginated_entries = array_slice($errors_master_list, $offset, $per_page);

    return [
        'entries' => $paginated_entries,
        'total_entries' => $total_entries,
        'total_pages' => ceil($total_entries / $per_page),
        'current_page' => $page
    ];
}

/**
 * Get file modification time for auto-refresh
 */
function custom_logs_get_file_mtime_callback()
{
    check_ajax_referer('custom_logs_filter_nonce', 'nonce');

    global $wp_filesystem;
    if (!WP_Filesystem()) {
        wp_send_json_error('Filesystem error');
    }

    $log_file = isset($_POST['log_file']) ? sanitize_text_field(wp_unslash($_POST['log_file'])) : '';

    if (!$wp_filesystem->exists($log_file)) {
        wp_send_json_success(['mtime' => 0]);
    }

    // Get file modification time (Unix timestamp)
    $mtime = filemtime($log_file);
    wp_send_json_success(['mtime' => $mtime]);
}
add_action('wp_ajax_custom_logs_get_file_mtime', 'custom_logs_get_file_mtime_callback');

/**
 * Updated filter logs callback to handle force refresh
 */
function custom_logs_filter_logs_callback()
{
    check_ajax_referer('custom_logs_filter_nonce', 'nonce');

    global $wp_filesystem;
    if (!WP_Filesystem()) {
        wp_send_json_error('Filesystem error');
    }

    $log_file = isset($_POST['log_file']) ? sanitize_text_field(wp_unslash($_POST['log_file'])) : '';
    $filter_type = isset($_POST['filter_type']) ? sanitize_text_field(wp_unslash($_POST['filter_type'])) : 'all';
    $page = isset($_POST['page']) ? absint($_POST['page']) : 1;
    $per_page = 100;

    if (!$wp_filesystem->exists($log_file)) {
        wp_send_json_success([
            'content' => '<p class="custom-logs-empty">' . esc_html__('No logs available for this file.', 'custom-logs') . '</p>',
            'current_page' => 1,
            'total_pages' => 1
        ]);
    }

    $log_data = custom_logs_process_entries($log_file, $page, $per_page);
    $entries = $log_data['entries'];
    $total_pages = $log_data['total_pages'];
    $current_page = $log_data['current_page'];

    $filtered_logs = '';
    foreach ($entries as $entry) {
        if ($filter_type === 'all' || stripos($entry['type'], $filter_type) !== false) {
            $timestamp = $entry['occurrences'][0];
            $count = count($entry['occurrences']);
            $filtered_logs .= "[$timestamp] [{$entry['type']}]: {$entry['details']} ($count occurrences)\n";
        }
    }

    if ($filtered_logs) {
        $content = '<pre>' . esc_html($filtered_logs) . '</pre>';
    } else {
        $content = '<p class="custom-logs-empty">' . esc_html__('No logs match the selected filter.', 'custom-logs') . '</p>';
    }

    wp_send_json_success([
        'content' => $content,
        'current_page' => $current_page,
        'total_pages' => $total_pages
    ]);
}

// Hook the AJAX handler
add_action('wp_ajax_custom_logs_filter_logs', 'custom_logs_filter_logs_callback');

function log_file_page()
{
    if (!current_user_can('manage_options')) {
        wp_die(esc_html__('You do not have sufficient permissions to access this page.', 'custom-logs'));
    }

    global $wp_filesystem;
    if (!WP_Filesystem()) {
        wp_die(esc_html__('Unable to initialize WP_Filesystem.', 'custom-logs'));
    }
    custom_logs('test2', 'info');
    $upload = wp_upload_dir();
    $default_log_dir_name = get_option('log_dir_name', 'custom-logs');
    $log_dir = $upload['basedir'] . '/' . $default_log_dir_name . '/';
    $wp_debug_dir = $log_dir . 'wp_debug/';
    $custom_debug_dir = $log_dir . 'custom_debug/';

    if (!$wp_filesystem->exists($log_dir)) {
        $wp_filesystem->mkdir($log_dir);
    }
    if (!$wp_filesystem->exists($wp_debug_dir)) {
        $wp_filesystem->mkdir($wp_debug_dir);
    }
    if (!$wp_filesystem->exists($custom_debug_dir)) {
        $wp_filesystem->mkdir($custom_debug_dir);
    }

    $default_log_file = $custom_debug_dir . 'debug.log';
    $default_wp_debug_log_file = $wp_debug_dir . 'wp-debug.log';
    $current_log_file = get_option('custom_logs_file_path', $default_log_file);
    $wp_debug_log_file = get_option('wp_debug_log_file_path', $default_wp_debug_log_file);
    $custom_log_files = $wp_filesystem->dirlist($custom_debug_dir) ?: [];
    $wp_debug_log_files = $wp_filesystem->dirlist($wp_debug_dir) ?: [];

    $custom_log_files = array_filter($custom_log_files, function ($file) {
        $name = strtolower($file['name']);
        return strpos($name, '.log') !== false;
    });
    $wp_debug_log_files = array_filter($wp_debug_log_files, function ($file) {
        $name = strtolower($file['name']);
        return strpos($name, '.log') !== false;
    });
    $all_log_files = array_merge(
        array_map(function ($file) use ($custom_debug_dir) {
            return ['name' => $file['name'], 'path' => $custom_debug_dir . $file['name']];
        }, $custom_log_files),
        array_map(function ($file) use ($wp_debug_dir) {
            return ['name' => $file['name'], 'path' => $wp_debug_dir . $file['name']];
        }, $wp_debug_log_files)
    );

    $selected_custom_log = isset($_POST['view_custom_log']) ? sanitize_text_field(wp_unslash($_POST['view_custom_log'])) : $current_log_file;
    $selected_wp_log = isset($_POST['view_wp_log']) ? sanitize_text_field(wp_unslash($_POST['view_wp_log'])) : $wp_debug_log_file;
    $custom_filter_type = isset($_POST['custom_filter_type']) ? sanitize_text_field(wp_unslash($_POST['custom_filter_type'])) : 'all';
    $wp_filter_type = isset($_POST['wp_filter_type']) ? sanitize_text_field(wp_unslash($_POST['wp_filter_type'])) : 'all';

    $wp_config = new CL_Config_Transformer();

    if (isset($_POST['set_log_dir_name']) && !empty($_POST['log_dir_name'])) {
        if (!wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['log_nonce'])), 'log_nonce_action')) {
            wp_die(esc_html__('Security check failed.', 'custom-logs'));
        }
        $log_dir_name = sanitize_file_name(wp_unslash($_POST['log_dir_name']));
        update_option('log_dir_name', $log_dir_name);
        $log_dir = $upload['basedir'] . '/' . $log_dir_name . '/';
        $wp_filesystem->mkdir($log_dir);
        $wp_filesystem->mkdir($log_dir . 'wp_debug/');
        $wp_filesystem->mkdir($log_dir . 'custom_debug/');
    }

    if (isset($_POST['set_log_name']) && !empty($_POST['log_file_name'])) {
        if (!wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['log_nonce'])), 'log_nonce_action')) {
            wp_die(esc_html__('Security check failed.', 'custom-logs'));
        }
        $log_file_name = sanitize_file_name(wp_unslash($_POST['log_file_name']));
        $new_log_file = $custom_debug_dir . $log_file_name;
        update_option('custom_logs_file_path', $new_log_file);
        if (!$wp_filesystem->exists($new_log_file)) {
            $timestamp = gmdate('Y-m-d H:i:s');
            $wp_filesystem->put_contents($new_log_file, "[$timestamp] [INFO]: New custom log file created: $log_file_name\n");
            $wp_filesystem->chmod($new_log_file, 0644);
        }
        $current_log_file = $new_log_file;
        $selected_custom_log = $new_log_file;
        $custom_log_files = $wp_filesystem->dirlist($custom_debug_dir) ?: [];
        $custom_log_files = array_filter($custom_log_files, function ($file) {
            $name = strtolower($file['name']);
            return strpos($name, '.log') !== false;
        });
        $all_log_files = array_merge(
            array_map(function ($file) use ($custom_debug_dir) {
                return ['name' => $file['name'], 'path' => $custom_debug_dir . $file['name']];
            }, $custom_log_files),
            array_map(function ($file) use ($wp_debug_dir) {
                return ['name' => $file['name'], 'path' => $wp_debug_dir . $file['name']];
            }, $wp_debug_log_files)
        );
    }

    if (isset($_POST['set_active_custom_log']) && !empty($_POST['active_custom_log'])) {
        if (!wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['log_nonce'])), 'log_nonce_action')) {
            wp_die(esc_html__('Security check failed.', 'custom-logs'));
        }
        $new_active_log = sanitize_text_field(wp_unslash($_POST['active_custom_log']));
        if ($wp_filesystem->exists($new_active_log)) {
            update_option('custom_logs_file_path', $new_active_log);
            $current_log_file = $new_active_log;
        }
    }

    if (isset($_POST['set_wp_debug_log_name']) && !empty($_POST['wp_debug_log_file_name'])) {
        if (!wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['log_nonce'])), 'log_nonce_action')) {
            wp_die(esc_html__('Security check failed.', 'custom-logs'));
        }
        $wp_debug_log_file_name = sanitize_file_name(wp_unslash($_POST['wp_debug_log_file_name']));
        $new_wp_debug_log_file = $wp_debug_dir . $wp_debug_log_file_name;

        // Ensure the file doesn’t already exist or handle it appropriately
        if (!$wp_filesystem->exists($new_wp_debug_log_file)) {
            $timestamp = gmdate('Y-m-d H:i:s');
            $wp_filesystem->put_contents($new_wp_debug_log_file, "[$timestamp] [INFO]: New WP debug log file created: $wp_debug_log_file_name\n");
            $wp_filesystem->chmod($new_wp_debug_log_file, 0644);
        }

        $wp_config->update('constant', 'WP_DEBUG_LOG', $new_wp_debug_log_file, ['add' => true, 'raw' => false]);
        update_option('wp_debug_log_file_path', $new_wp_debug_log_file);

        // If WP_DEBUG is enabled, move existing logs if necessary
        if ($wp_config->exists('constant', 'WP_DEBUG_LOG')) {
            $existing_log = $wp_config->get_value('constant', 'WP_DEBUG_LOG');
            if ($existing_log && $existing_log !== 'true' && $existing_log !== 'false' && $existing_log !== $new_wp_debug_log_file) {
                if (is_file($existing_log)) {
                    $content = file_get_contents($existing_log);
                    $wp_filesystem->put_contents($new_wp_debug_log_file, $content, FILE_APPEND);
                    unlink($existing_log);
                }
            }
        }

        $wp_debug_log_file = $new_wp_debug_log_file;
        $selected_wp_log = $new_wp_debug_log_file;

        // Refresh WP debug log files list
        $wp_debug_log_files = $wp_filesystem->dirlist($wp_debug_dir) ?: [];
        $wp_debug_log_files = array_filter($wp_debug_log_files, function ($file) {
            $name = strtolower($file['name']);
            return strpos($name, '.log') !== false;
        });
        $all_log_files = array_merge(
            array_map(function ($file) use ($custom_debug_dir) {
                return ['name' => $file['name'], 'path' => $custom_debug_dir . $file['name']];
            }, $custom_log_files),
            array_map(function ($file) use ($wp_debug_dir) {
                return ['name' => $file['name'], 'path' => $wp_debug_dir . $file['name']];
            }, $wp_debug_log_files)
        );
    }

    if (isset($_POST['set_active_wp_debug_log']) && !empty($_POST['active_wp_debug_log'])) {
        if (!wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['log_nonce'])), 'log_nonce_action')) {
            wp_die(esc_html__('Security check failed.', 'custom-logs'));
        }
        $new_active_wp_log = sanitize_text_field(wp_unslash($_POST['active_wp_debug_log']));
        if ($wp_filesystem->exists($new_active_wp_log)) {
            $wp_config->update('constant', 'WP_DEBUG_LOG', $new_active_wp_log, ['add' => true, 'raw' => false]);
            update_option('wp_debug_log_file_path', $new_active_wp_log);
            $wp_debug_log_file = $new_active_wp_log;
        }
    }

    if (isset($_POST['clear_log']) && !empty($_POST['test_log_file'])) {
        if (!wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['log_nonce'])), 'log_nonce_action')) {
            wp_die(esc_html__('Security check failed.', 'custom-logs'));
        }
        $file_to_clear = sanitize_text_field(wp_unslash($_POST['test_log_file']));
        if ($wp_filesystem->exists($file_to_clear)) {
            $wp_filesystem->put_contents($file_to_clear, '');
        }
    }

    if (isset($_POST['backup_log']) && $wp_filesystem->exists($current_log_file)) {
        if (!wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['log_nonce'])), 'log_nonce_action')) {
            wp_die(esc_html__('Security check failed.', 'custom-logs'));
        }

        // Get the base filename without path and extension
        $current_filename = basename($current_log_file, '.log'); // e.g., 'debug' from 'debug.log'
        $timestamp = time(); // Current UNIX timestamp
        $backup_file = $custom_debug_dir . $current_filename . '-backup-' . $timestamp . '.log'; // e.g., 'custom_debug/debug-backup-1698765432.log'

        // Copy the current log file to the backup location
        $wp_filesystem->copy($current_log_file, $backup_file);
        $wp_filesystem->chmod($backup_file, 0644);

        // Refresh the list of custom log files
        $custom_log_files = $wp_filesystem->dirlist($custom_debug_dir) ?: [];
        $custom_log_files = array_filter($custom_log_files, function ($file) {
            $name = strtolower($file['name']);
            return strpos($name, '.log') !== false;
        });

        // Update the combined list of all log files
        $all_log_files = array_merge(
            array_map(function ($file) use ($custom_debug_dir) {
                return ['name' => $file['name'], 'path' => $custom_debug_dir . $file['name']];
            }, $custom_log_files),
            array_map(function ($file) use ($wp_debug_dir) {
                return ['name' => $file['name'], 'path' => $wp_debug_dir . $file['name']];
            }, $wp_debug_log_files)
        );
    }

    if (isset($_POST['delete_log']) && !empty($_POST['test_log_file'])) {
        if (!wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['log_nonce'])), 'log_nonce_action')) {
            wp_die(esc_html__('Security check failed.', 'custom-logs'));
        }
        $delete_file = sanitize_text_field(wp_unslash($_POST['test_log_file']));
        if ($wp_filesystem->exists($delete_file)) {
            $wp_filesystem->delete($delete_file);

            // Refresh file lists
            $custom_log_files = $wp_filesystem->dirlist($custom_debug_dir) ?: [];
            $wp_debug_log_files = $wp_filesystem->dirlist($wp_debug_dir) ?: [];
            $custom_log_files = array_filter($custom_log_files, function ($file) {
                $name = strtolower($file['name']);
                return strpos($name, '.log') !== false;
            });
            $wp_debug_log_files = array_filter($wp_debug_log_files, function ($file) {
                $name = strtolower($file['name']);
                return strpos($name, '.log') !== false;
            });
            $all_log_files = array_merge(
                array_map(function ($file) use ($custom_debug_dir) {
                    return ['name' => $file['name'], 'path' => $custom_debug_dir . $file['name']];
                }, $custom_log_files),
                array_map(function ($file) use ($wp_debug_dir) {
                    return ['name' => $file['name'], 'path' => $wp_debug_dir . $file['name']];
                }, $wp_debug_log_files)
            );

            // Reset selections if the deleted file was active
            if ($selected_custom_log === $delete_file) {
                $selected_custom_log = $current_log_file;
            }
            if ($selected_wp_log === $delete_file) {
                $selected_wp_log = $wp_debug_log_file;
            }
            if ($current_log_file === $delete_file) {
                update_option('custom_logs_file_path', $default_log_file);
                $current_log_file = $default_log_file;
            }
            if ($wp_debug_log_file === $delete_file) {
                update_option('wp_debug_log_file_path', $default_wp_debug_log_file);
                $wp_debug_log_file = $default_wp_debug_log_file;
                $wp_config->update('constant', 'WP_DEBUG_LOG', $default_wp_debug_log_file, ['add' => true, 'raw' => false]);
            }
        }
    }

    if (isset($_POST['delete_all_backups'])) {
        if (!wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['log_nonce'])), 'log_nonce_action')) {
            wp_die(esc_html__('Security check failed.', 'custom-logs'));
        }
        foreach ($all_log_files as $file) {
            $wp_filesystem->delete($file['path']);
        }
        $custom_log_files = $wp_filesystem->dirlist($custom_debug_dir) ?: [];
        $wp_debug_log_files = $wp_filesystem->dirlist($wp_debug_dir) ?: [];
        $custom_log_files = array_filter($custom_log_files, function ($file) {
            $name = strtolower($file['name']);
            return strpos($name, '.log') !== false;
        });
        $wp_debug_log_files = array_filter($wp_debug_log_files, function ($file) {
            $name = strtolower($file['name']);
            return strpos($name, '.log') !== false;
        });
        $all_log_files = array_merge(
            array_map(function ($file) use ($custom_debug_dir) {
                return ['name' => $file['name'], 'path' => $custom_debug_dir . $file['name']];
            }, $custom_log_files),
            array_map(function ($file) use ($wp_debug_dir) {
                return ['name' => $file['name'], 'path' => $wp_debug_dir . $file['name']];
            }, $wp_debug_log_files)
        );
    }

    if (isset($_POST['test_log']) && !empty($_POST['test_log_file'])) {
        if (!wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['log_nonce'])), 'log_nonce_action')) {
            wp_die(esc_html__('Security check failed.', 'custom-logs'));
        }
        $test_log_file = sanitize_text_field(wp_unslash($_POST['test_log_file']));
        if ($wp_filesystem->exists($test_log_file)) {
            $timestamp = gmdate('Y-m-d H:i:s');
            $test_content = "[$timestamp] [INFO]: This is a test log entry.\n" .
                "[$timestamp] [ERROR]: This is a test error entry.\n";
            $existing_content = $wp_filesystem->get_contents($test_log_file) ?: '';
            $new_content = $existing_content . $test_content;
            $wp_filesystem->put_contents($test_log_file, $new_content);
            $wp_filesystem->chmod($test_log_file, 0644);
            if (strpos($test_log_file, $custom_debug_dir) === 0) {
                $selected_custom_log = $test_log_file;
            } elseif (strpos($test_log_file, $wp_debug_dir) === 0) {
                $selected_wp_log = $test_log_file;
            }
        }
    }

    if (isset($_POST['enable_logging'])) {
        if (!wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['log_nonce'])), 'log_nonce_action')) {
            wp_die(esc_html__('Security check failed.', 'custom-logs'));
        }
        update_option('logging_enabled', true);
    }

    if (isset($_POST['disable_logging'])) {
        if (!wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['log_nonce'])), 'log_nonce_action')) {
            wp_die(esc_html__('Security check failed.', 'custom-logs'));
        }
        update_option('logging_enabled', false);
    }

    if (isset($_POST['set_log_level']) && !empty($_POST['log_level'])) {
        if (!wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['log_nonce'])), 'log_nonce_action')) {
            wp_die(esc_html__('Security check failed.', 'custom-logs'));
        }
        update_option('log_level', sanitize_text_field(wp_unslash($_POST['log_level'])));
    }

    if (isset($_POST['enable_capture_wp_debug_logs'])) {
        if (!wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['log_nonce'])), 'log_nonce_action')) {
            wp_die(esc_html__('Security check failed.', 'custom-logs'));
        }
        update_option('capture_wp_debug_logs', true);
        custom_logs_capture_wp_debug_logs();
    }

    if (isset($_POST['set_wp_debug_level']) && !empty($_POST['wp_debug_level'])) {
        if (!wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['log_nonce'])), 'log_nonce_action')) {
            wp_die(esc_html__('Security check failed.', 'custom-logs'));
        }
        $new_wp_debug_level = sanitize_text_field(wp_unslash($_POST['wp_debug_level']));
        update_option('wp_debug_level', $new_wp_debug_level);
        $wp_debug_level = $new_wp_debug_level;
    }

    if (isset($_POST['disable_capture_wp_debug_logs'])) {
        if (!wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['log_nonce'])), 'log_nonce_action')) {
            wp_die(esc_html__('Security check failed.', 'custom-logs'));
        }
        update_option('capture_wp_debug_logs', false);
        $wp_config->remove('constant', 'WP_DEBUG');
        $wp_config->remove('constant', 'SCRIPT_DEBUG');
        $wp_config->remove('constant', 'WP_DEBUG_LOG');
        $wp_config->remove('constant', 'WP_DEBUG_DISPLAY');
    }

    $logging_enabled = get_option('logging_enabled', false);
    $log_level = get_option('log_level', 'none');
    $capture_wp_debug_logs = get_option('capture_wp_debug_logs', false);

    $custom_log_data = custom_logs_process_entries($selected_custom_log);
    $wp_log_data = custom_logs_process_entries($selected_wp_log);
    $custom_entries = $custom_log_data['entries'] ?? [];
    $wp_entries = $wp_log_data['entries'] ?? [];
    $wp_debug_level = get_option('wp_debug_level', 'all');

    // Sort custom entries by timestamp (newest first)
    usort($custom_entries, function ($a, $b) {
        $a_time = strtotime($a['occurrences'][0]);
        $b_time = strtotime($b['occurrences'][0]);
        return $b_time - $a_time; // Descending order
    });

    // Sort WP entries by timestamp (newest first)
    usort($wp_entries, function ($a, $b) {
        $a_time = strtotime($a['occurrences'][0]);
        $b_time = strtotime($b['occurrences'][0]);
        return $b_time - $a_time; // Descending order
    });

    $filtered_custom_logs = '';
    foreach ($custom_entries as $entry) {
        if ($custom_filter_type === 'all' || stripos($entry['type'], $custom_filter_type) !== false) {
            $timestamp = $entry['occurrences'][0];
            $count = count($entry['occurrences']);
            $filtered_custom_logs .= "[$timestamp] [{$entry['type']}]: {$entry['details']} ($count occurrences)\n";
        }
    }

    $filtered_wp_logs = '';
    foreach ($wp_entries as $entry) {
        if ($wp_filter_type === 'all' || stripos($entry['type'], $wp_filter_type) !== false) {
            $timestamp = $entry['occurrences'][0];
            $count = count($entry['occurrences']);
            $filtered_wp_logs .= "[$timestamp] [{$entry['type']}]: {$entry['details']} ($count occurrences)\n";
        }
    }

?>

    <div class="wrap custom-logs-wrap">
        <h1><?php echo esc_html__('Custom Logs', 'custom-logs'); ?></h1>
        <form method="post" class="custom-logs-form">
            <?php wp_nonce_field('log_nonce_action', 'log_nonce'); ?>

            <!-- How To Accordion -->
            <details class="accordion">
                <summary class="accordion-header"><?php echo esc_html__('How To Use Custom Logs', 'custom-logs'); ?></summary>
                <div class="accordion-content">
                    <p><?php echo esc_html__('The custom_logs function allows you to log messages to the active custom log file. Here’s how to use it:', 'custom-logs'); ?></p>
                    <ul>
                        <li><strong><?php echo esc_html__('Enable Logging:', 'custom-logs'); ?></strong> <?php echo esc_html__('Go to the "Custom Logging" section below and click "Enable".', 'custom-logs'); ?></li>
                        <li><strong><?php echo esc_html__('Function Syntax:', 'custom-logs'); ?></strong> <code>custom_logs($message, $type)</code></li>
                        <li><strong><?php echo esc_html__('Parameters:', 'custom-logs'); ?></strong>
                            <ul>
                                <li><code>$message</code>: <?php echo esc_html__('The message to log (string).', 'custom-logs'); ?></li>
                                <li><code>$type</code>: <?php echo esc_html__('The log level (string). Options: "info" (default), "error", "warning", "notice".', 'custom-logs'); ?></li>
                            </ul>
                        </li>
                        <li><strong><?php echo esc_html__('Example Usage:', 'custom-logs'); ?></strong>
                            <pre><?php
                                    // Use heredoc with indentation in source code
                                    $example_code = <<<EOD
                                <?php
                                    // Log an info message
                                    custom_logs("User logged in successfully", "info");

                                    // Log an error
                                    custom_logs("Database connection failed", "error");

                                    // Log a warning
                                    custom_logs("Deprecated function used", "warning");

                                    // Log a notice
                                    custom_logs("Settings updated", "notice");
                                ?>
                                EOD;
                                    // Remove leading whitespace from each line
                                    $lines = explode("\n", $example_code);
                                    $trimmed_lines = array_map(function ($line) {
                                        return ltrim($line); // Remove leading spaces/tabs
                                    }, $lines);
                                    $trimmed_code = implode("\n", $trimmed_lines);
                                    echo esc_html($trimmed_code);
                                    ?></pre>
                        </li>
                        <li><strong><?php echo esc_html__('Notes:', 'custom-logs'); ?></strong>
                            <ul>
                                <li><?php echo esc_html__('Logging must be enabled for messages to be recorded.', 'custom-logs'); ?></li>
                                <li><?php echo esc_html__('The log level must match or exceed the "Set Custom Log Level" setting to be logged.', 'custom-logs'); ?></li>
                                <li><?php echo esc_html__('Logs are stored in the custom debug directory (e.g., wp-content/uploads/custom-logs/custom_debug/).', 'custom-logs'); ?></li>
                            </ul>
                        </li>
                    </ul>
                </div>
            </details>
            <!-- Rest of your HTML remains unchanged -->
            <div class="custom-logs-viewer">
                <div class="log-row">
                    <div class="log-column custom-log-viewer">
                        <div class="custom-logs-section">
                            <h2><?php echo esc_html__('General', 'custom-logs'); ?></h2>
                            <div class="control-group">
                                <div class="input-wrapper">
                                    <label for="log_dir_name"><?php echo esc_html__('Log Directory Name', 'custom-logs'); ?></label>
                                    <div class="input-group">
                                        <input type="text" id="log_dir_name" name="log_dir_name" value="<?php echo esc_attr($default_log_dir_name); ?>" placeholder="custom-logs">
                                        <button type="submit" name="set_log_dir_name" class="custom-logs-btn primary"><?php echo esc_html__('Set', 'custom-logs'); ?></button>
                                    </div>
                                    <?php $log_dir_message = sprintf('This folder will be created in the uploads directory (%s).', esc_html($upload['basedir'])); ?>
                                    <p class="description"><?php echo esc_html($log_dir_message); ?></p>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="log-column custom-log-viewer">
                        <div class="custom-logs-section">
                            <h2><?php echo esc_html__('Management', 'custom-logs'); ?></h2>
                            <div class="control-group">
                                <div class="input-wrapper">
                                    <label><?php echo esc_html__('Actions', 'custom-logs'); ?></label>
                                    <div class="input-group">
                                        <select name="test_log_file">
                                            <?php foreach ($all_log_files as $file) { ?>
                                                <option value="<?php echo esc_attr($file['path']); ?>" <?php echo $file['path'] === $selected_custom_log ? 'selected' : ''; ?>><?php echo esc_html($file['name']); ?></option>
                                            <?php } ?>
                                        </select>
                                        <button type="submit" name="test_log" class="custom-logs-btn secondary"><?php echo esc_html__('Test', 'custom-logs'); ?></button>
                                        <button type="submit" name="clear_log" class="custom-logs-btn secondary"><?php echo esc_html__('Clear', 'custom-logs'); ?></button>
                                        <button type="submit" name="backup_log" class="custom-logs-btn secondary"><?php echo esc_html__('Backup', 'custom-logs'); ?></button>
                                        <button type="submit" name="download_log" class="custom-logs-btn primary"><?php echo esc_html__('Download', 'custom-logs'); ?></button>
                                        <button type="submit" name="delete_log" class="custom-logs-btn danger"><?php echo esc_html__('Delete', 'custom-logs'); ?></button>
                                        <button type="submit" name="delete_all_backups" class="custom-logs-btn secondary"><?php echo esc_html__('Delete All Backups', 'custom-logs'); ?></button>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="custom-logs-viewer">
                    <div class="log-row">
                        <div class="log-column custom-log-viewer">
                            <div class="custom-logs-viewer-section">
                                <div class="viewer-header">
                                    <h2><?php echo esc_html__('Custom Log Viewer', 'custom-logs'); ?></h2>
                                    <div class="input-group">
                                        <div class="input-wrapper">
                                            <label for="view_custom_log"><?php echo esc_html__('Select Custom Log', 'custom-logs'); ?></label>
                                            <select id="view_custom_log" name="view_custom_log">
                                                <?php foreach ($custom_log_files as $file) {
                                                    $file_path = $custom_debug_dir . $file['name'];
                                                    $selected = $file_path === $current_log_file ? 'selected' : '';
                                                ?>
                                                    <option value="<?php echo esc_attr($file_path); ?>" <?php echo esc_attr($selected); ?>><?php echo esc_html($file['name']); ?></option>
                                                <?php } ?>
                                            </select>
                                        </div>
                                        <div class="input-wrapper">
                                            <label for="custom_filter_type"><?php echo esc_html__('Filter by Type', 'custom-logs'); ?></label>
                                            <select id="custom_filter_type" name="custom_filter_type">
                                                <option value="all" <?php selected($custom_filter_type, 'all'); ?>><?php echo esc_html__('All', 'custom-logs'); ?></option>
                                                <option value="INFO" <?php selected($custom_filter_type, 'INFO'); ?>><?php echo esc_html__('Info', 'custom-logs'); ?></option>
                                                <option value="ERROR" <?php selected($custom_filter_type, 'ERROR'); ?>><?php echo esc_html__('Error', 'custom-logs'); ?></option>
                                                <option value="WARNING" <?php selected($custom_filter_type, 'WARNING'); ?>><?php echo esc_html__('Warning', 'custom-logs'); ?></option>
                                                <option value="NOTICE" <?php selected($custom_filter_type, 'NOTICE'); ?>><?php echo esc_html__('Notice', 'custom-logs'); ?></option>
                                            </select>
                                        </div>
                                    </div>
                                </div>
                                <div class="viewer-content" id="custom-logs-viewer-content">
                                    <?php if ($filtered_custom_logs) { ?>
                                        <pre><?php echo esc_html($filtered_custom_logs); ?></pre>
                                    <?php } else { ?>
                                        <p class="no-logs"><?php echo esc_html__('No custom logs available.', 'custom-logs'); ?></p>
                                    <?php } ?>
                                </div>
                                <div class="viewer-pagination" id="custom-logs-pagination">
                                    <span class="page-count" id="custom-page-count"></span>

                                    <button class="custom-logs-btn secondary custom-logs-prev" data-page="1" disabled>Previous</button>
                                    <button class="custom-logs-btn secondary custom-logs-next" data-page="1" disabled>Next</button>
                                </div>
                            </div>
                            <div class="custom-logs-section">
                                <h2><?php echo esc_html__('Custom Logging', 'custom-logs'); ?></h2>
                                <div class="control-group">
                                    <div class="input-wrapper">
                                        <label for="log_file_name"><?php echo esc_html__('Create New Log File', 'custom-logs'); ?></label>
                                        <div class="input-group">
                                            <input type="text" id="log_file_name" name="log_file_name" value="" placeholder="debug.log">
                                            <button type="submit" name="set_log_name" class="custom-logs-btn primary"><?php echo esc_html__('Create', 'custom-logs'); ?></button>
                                        </div>
                                    </div>
                                    <div class="input-wrapper">
                                        <label for="active_custom_log"><?php echo esc_html__('Active Custom Log', 'custom-logs'); ?></label>
                                        <div class="input-group">
                                            <select id="active_custom_log" name="active_custom_log">
                                                <?php foreach ($custom_log_files as $file) {
                                                    $file_path = $custom_debug_dir . $file['name'];
                                                    $selected = $file_path === $current_log_file ? 'selected' : '';
                                                ?>
                                                    <option value="<?php echo esc_attr($file_path); ?>" <?php echo esc_attr($selected); ?>><?php echo esc_html($file['name']); ?></option>
                                                <?php } ?>
                                            </select>
                                            <button type="submit" name="set_active_custom_log" class="custom-logs-btn primary"><?php echo esc_html__('Set', 'custom-logs'); ?></button>
                                        </div>
                                    </div>
                                    <div class="input-wrapper">
                                        <label><?php echo esc_html__('Enable Logging', 'custom-logs'); ?></label>
                                        <div class="input-group">
                                            <button type="submit" name="<?php echo $logging_enabled ? 'disable_logging' : 'enable_logging'; ?>" class="custom-logs-btn <?php echo $logging_enabled ? 'secondary' : 'primary'; ?>">
                                                <?php echo $logging_enabled ? esc_html__('Disable', 'custom-logs') : esc_html__('Enable', 'custom-logs'); ?>
                                            </button>
                                        </div>
                                    </div>
                                    <div class="input-wrapper">
                                        <label for="log_level"><?php echo esc_html__('Set Custom Log Level', 'custom-logs'); ?></label>
                                        <div class="input-group">
                                            <select id="log_level" name="log_level">
                                                <option value="none" <?php selected($log_level, 'none'); ?>><?php echo esc_html__('None', 'custom-logs'); ?></option>
                                                <option value="all" <?php selected($log_level, 'all'); ?>><?php echo esc_html__('All', 'custom-logs'); ?></option>
                                                <option value="error" <?php selected($log_level, 'error'); ?>><?php echo esc_html__('Errors', 'custom-logs'); ?></option>
                                                <option value="warning" <?php selected($log_level, 'warning'); ?>><?php echo esc_html__('Warnings', 'custom-logs'); ?></option>
                                                <option value="notice" <?php selected($log_level, 'notice'); ?>><?php echo esc_html__('Notices', 'custom-logs'); ?></option>
                                            </select>
                                            <button type="submit" name="set_log_level" class="custom-logs-btn primary"><?php echo esc_html__('Set', 'custom-logs'); ?></button>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                        <div class="log-column wp-debug-viewer">
                            <div class="custom-logs-viewer-section">
                                <div class="viewer-header">
                                    <h2><?php echo esc_html__('WP Debug Log Viewer', 'custom-logs'); ?></h2>
                                    <div class="input-group">
                                        <div class="input-wrapper">
                                            <label for="view_wp_log"><?php echo esc_html__('Select WP Log', 'custom-logs'); ?></label>
                                            <select id="view_wp_log" name="view_wp_log">
                                                <?php foreach ($wp_debug_log_files as $file) {
                                                    $file_path = $wp_debug_dir . $file['name'];
                                                    $selected = $file_path === $selected_wp_log ? 'selected' : '';
                                                ?>
                                                    <option value="<?php echo esc_attr($file_path); ?>" <?php echo esc_attr($selected); ?>><?php echo esc_html($file['name']); ?></option>
                                                <?php } ?>
                                            </select>
                                        </div>
                                        <div class="input-wrapper">
                                            <label for="wp_filter_type"><?php echo esc_html__('Filter by Type', 'custom-logs'); ?></label>
                                            <select id="wp_filter_type" name="wp_filter_type">
                                                <option value="all" <?php selected($wp_filter_type, 'all'); ?>><?php echo esc_html__('All', 'custom-logs'); ?></option>
                                                <option value="PHP Fatal" <?php selected($wp_filter_type, 'PHP Fatal'); ?>><?php echo esc_html__('PHP Fatal', 'custom-logs'); ?></option>
                                                <option value="PHP Warning" <?php selected($wp_filter_type, 'PHP Warning'); ?>><?php echo esc_html__('PHP Warning', 'custom-logs'); ?></option>
                                                <option value="PHP Notice" <?php selected($wp_filter_type, 'PHP Notice'); ?>><?php echo esc_html__('PHP Notice', 'custom-logs'); ?></option>
                                                <option value="PHP Deprecated" <?php selected($wp_filter_type, 'PHP Deprecated'); ?>><?php echo esc_html__('PHP Deprecated', 'custom-logs'); ?></option>
                                                <option value="PHP Parse" <?php selected($wp_filter_type, 'PHP Parse'); ?>><?php echo esc_html__('PHP Parse', 'custom-logs'); ?></option>
                                                <option value="PHP Exception" <?php selected($wp_filter_type, 'PHP Exception'); ?>><?php echo esc_html__('PHP Exception', 'custom-logs'); ?></option>
                                                <option value="Database" <?php selected($wp_filter_type, 'Database'); ?>><?php echo esc_html__('Database', 'custom-logs'); ?></option>
                                                <option value="Other" <?php selected($wp_filter_type, 'Other'); ?>><?php echo esc_html__('Other', 'custom-logs'); ?></option>
                                            </select>
                                        </div>
                                    </div>
                                </div>
                                <div class="viewer-content" id="wp-logs-viewer-content">
                                    <?php if ($filtered_wp_logs) { ?>
                                        <pre><?php echo esc_html($filtered_wp_logs); ?></pre>
                                    <?php } else { ?>
                                        <p class="no-logs"><?php echo esc_html__('No WP debug logs available.', 'custom-logs'); ?></p>
                                    <?php } ?>
                                </div>
                                <div class="viewer-pagination" id="wp-logs-pagination">
                                    <span class="page-count" id="wp-page-count"></span>

                                    <button class="custom-logs-btn secondary custom-logs-prev" data-page="1" disabled>Previous</button>
                                    <button class="custom-logs-btn secondary custom-logs-next" data-page="1" disabled>Next</button>
                                </div>
                            </div>
                            <div class="custom-logs-section">
                                <h2><?php echo esc_html__('WP Debug Logging', 'custom-logs'); ?></h2>
                                <div class="control-group">
                                    <div class="input-wrapper">
                                        <label for="wp_debug_log_file_name"><?php echo esc_html__('Create New WP Debug Log', 'custom-logs'); ?></label>
                                        <div class="input-group">
                                            <input type="text" id="wp_debug_log_file_name" name="wp_debug_log_file_name" value="" placeholder="wp-debug.log">
                                            <button type="submit" name="set_wp_debug_log_name" class="custom-logs-btn primary"><?php echo esc_html__('Create', 'custom-logs'); ?></button>
                                        </div>
                                    </div>
                                    <div class="input-wrapper">
                                        <label for="active_wp_debug_log"><?php echo esc_html__('Active WP Debug Log', 'custom-logs'); ?></label>
                                        <div class="input-group">
                                            <select id="active_wp_debug_log" name="active_wp_debug_log">
                                                <?php foreach ($wp_debug_log_files as $file) {
                                                    $file_path = $wp_debug_dir . $file['name'];
                                                    $selected = $file_path === $wp_debug_log_file ? 'selected' : '';
                                                ?>
                                                    <option value="<?php echo esc_attr($file_path); ?>" <?php echo esc_attr($selected); ?>><?php echo esc_html($file['name']); ?></option>
                                                <?php } ?>
                                            </select>
                                            <button type="submit" name="set_active_wp_debug_log" class="custom-logs-btn primary"><?php echo esc_html__('Set', 'custom-logs'); ?></button>
                                        </div>
                                    </div>
                                    <div class="input-wrapper">
                                        <label><?php echo esc_html__('Capture WP Debug', 'custom-logs'); ?></label>
                                        <div class="input-group">
                                            <button type="submit" name="<?php echo $capture_wp_debug_logs ? 'disable_capture_wp_debug_logs' : 'enable_capture_wp_debug_logs'; ?>" class="custom-logs-btn <?php echo $capture_wp_debug_logs ? 'secondary' : 'primary'; ?>">
                                                <?php echo $capture_wp_debug_logs ? esc_html__('Disable', 'custom-logs') : esc_html__('Enable', 'custom-logs'); ?>
                                            </button>
                                        </div>
                                    </div>
                                    <div class="input-wrapper">
                                        <label for="wp_debug_level"><?php echo esc_html__('Set Debug Log Level', 'custom-logs'); ?></label>
                                        <div class="input-group">
                                            <select id="wp_debug_level" name="wp_debug_level">
                                                <option value="all" <?php selected($wp_debug_level, 'all'); ?>><?php echo esc_html__('All', 'custom-logs'); ?></option>
                                                <option value="PHP Fatal" <?php selected($wp_debug_level, 'PHP Fatal'); ?>><?php echo esc_html__('PHP Fatal', 'custom-logs'); ?></option>
                                                <option value="PHP Warning" <?php selected($wp_debug_level, 'PHP Warning'); ?>><?php echo esc_html__('PHP Warning', 'custom-logs'); ?></option>
                                                <option value="PHP Notice" <?php selected($wp_debug_level, 'PHP Notice'); ?>><?php echo esc_html__('PHP Notice', 'custom-logs'); ?></option>
                                                <option value="PHP Deprecated" <?php selected($wp_debug_level, 'PHP Deprecated'); ?>><?php echo esc_html__('PHP Deprecated', 'custom-logs'); ?></option>
                                                <option value="PHP Parse" <?php selected($wp_debug_level, 'PHP Parse'); ?>><?php echo esc_html__('PHP Parse', 'custom-logs'); ?></option>
                                                <option value="PHP Exception" <?php selected($wp_debug_level, 'PHP Exception'); ?>><?php echo esc_html__('PHP Exception', 'custom-logs'); ?></option>
                                                <option value="Database" <?php selected($wp_debug_level, 'Database'); ?>><?php echo esc_html__('Database', 'custom-logs'); ?></option>
                                                <option value="Other" <?php selected($wp_debug_level, 'Other'); ?>><?php echo esc_html__('Other', 'custom-logs'); ?></option>
                                            </select>
                                            <button type="submit" name="set_wp_debug_level" class="custom-logs-btn primary"><?php echo esc_html__('Set', 'custom-logs'); ?></button>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
        </form>
    </div>

<?php
}

/* ----- AJAX Handlers ----- */
add_action('wp_ajax_custom_logs_filter_logs', 'custom_logs_filter_logs');
function custom_logs_filter_logs()
{
    check_ajax_referer('custom_logs_filter_nonce', 'nonce');

    global $wp_filesystem;
    if (!WP_Filesystem()) {
        wp_send_json_error('Filesystem error');
    }

    $log_file = isset($_POST['log_file']) ? sanitize_text_field(wp_unslash($_POST['log_file'])) : '';
    $filter_type = isset($_POST['filter_type']) ? sanitize_text_field(wp_unslash($_POST['filter_type'])) : 'all';

    if (!$wp_filesystem->exists($log_file)) {
        wp_send_json_success('<p class="custom-logs-empty">' . esc_html__('No logs available for this file.', 'custom-logs') . '</p>');
    }

    $entries = custom_logs_process_entries($log_file);
    $filtered_logs = '';
    foreach ($entries as $entry) {
        if ($filter_type === 'all' || stripos($entry['type'], $filter_type) !== false) {
            $timestamp = end($entry['occurrences']);
            $count = count($entry['occurrences']);
            $filtered_logs .= "[$timestamp] [{$entry['type']}]: {$entry['details']} ($count occurrences)\n";
        }
    }

    if ($filtered_logs) {
        wp_send_json_success('<pre>' . esc_html($filtered_logs) . '</pre>');
    } else {
        wp_send_json_success('<p class="custom-logs-empty">' . esc_html__('No logs match the selected filter.', 'custom-logs') . '</p>');
    }
}

add_action('wp_ajax_download_log_file', 'download_log_file');
function download_log_file()
{
    if (!isset($_GET['_wpnonce']) || !wp_verify_nonce(sanitize_text_field(wp_unslash($_GET['_wpnonce'])), 'download_log_file_nonce')) {
        wp_die(esc_html__('Security check failed.', 'custom-logs'));
    }

    global $wp_filesystem;
    if (!WP_Filesystem()) {
        wp_die(esc_html__('Unable to initialize WP_Filesystem.', 'custom-logs'));
    }

    $log_file = isset($_GET['log_file']) ? sanitize_text_field(wp_unslash($_GET['log_file'])) : '';
    if (!empty($log_file) && $wp_filesystem->exists($log_file)) {
        header('Content-Type: text/plain');
        header('Content-Disposition: attachment; filename="' . basename($log_file) . '"');
        echo esc_html($wp_filesystem->get_contents($log_file));
        exit;
    }
    wp_die(esc_html__('Log file not found.', 'custom-logs'));
}


function custom_logs($message, $type = 'info')
{
    $logging_enabled = get_option('logging_enabled', false);
    $log_level = get_option('log_level', 'all');

    if (!$logging_enabled || !should_log($type, $log_level)) {
        return false;
    }

    try {
        $upload = wp_upload_dir();
        $log_dir_name = get_option('log_dir_name', 'custom-logs');
        $log_dir = $upload['basedir'] . '/' . $log_dir_name . '/';
        $custom_debug_dir = $log_dir . 'custom_debug/';
        $current_log_file = get_option('custom_logs_file_path', $custom_debug_dir . 'debug.log');

        // Ensure the directory exists
        if (!file_exists($custom_debug_dir)) {
            wp_mkdir_p($custom_debug_dir);
            chmod($custom_debug_dir, 0755); // Ensure directory is writable
        }

        $timestamp = gmdate('Y-m-d H:i:s');
        $formatted_message = sprintf("[%s] [%s]: %s%s", $timestamp, strtoupper($type), $message, PHP_EOL);

        // Use native PHP file handling to append the log entry
        $file_handle = fopen($current_log_file, 'a'); // Open file in append mode
        if ($file_handle) {
            fwrite($file_handle, $formatted_message); // Append the log entry
            fclose($file_handle); // Close the file handle
            chmod($current_log_file, 0644); // Set permissions to 644
            return true;
        } else {
            return false; // Failed to open the file
        }
    } catch (Exception $e) {
        return false;
    }
}

function should_log($type, $log_level)
{
    $log_levels = [
        'none' => [],
        'all' => ['error', 'warning', 'notice', 'info'],
        'error' => ['error'],
        'warning' => ['error', 'warning'],
        'notice' => ['error', 'warning', 'notice'],
        'info' => ['error', 'warning', 'notice', 'info']
    ];

    return in_array(strtolower($type), $log_levels[strtolower($log_level)]);
}
