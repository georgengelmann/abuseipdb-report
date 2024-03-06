<?php
/**
 * Plugin Name: AbuseIPDB Report with All-in-One WP Security Integration
 * Description: Report failed login attempts to AbuseIPDB after checking if the All-in-One WP Security plugin is enabled and then checking the plugin's table.
 * Version: 1.0
 * Author: Georg Engelmann <mail@georg-engelmann.at>
 */

// Register WordPress hooks
add_action('admin_menu', 'abuseipdb_menu');
add_action('wp_login_failed', 'report_failed_login', 10, 2);
register_activation_hook(__FILE__, 'abuseipdb_activate');
register_deactivation_hook(__FILE__, 'abuseipdb_deactivate');

// Function to create the admin settings menu
function abuseipdb_menu() {
    add_options_page('AbuseIPDB Report Settings', 'AbuseIPDB Report Settings', 'manage_options', 'abuseipdb-settings', 'abuseipdb_settings_page');
    register_setting('abuseipdb-settings-group', 'abuseipdb_api_key');
}

// Function to display the settings page
function abuseipdb_settings_page() {
    if (!current_user_can('manage_options')) {
        wp_die('You do not have sufficient permissions to access this page.');
    }

    ?>
    <div class="wrap">
        <h2>AbuseIPDB Report Settings</h2>
        <form method="post" action="options.php">
            <?php settings_fields('abuseipdb-settings-group'); ?>
            <table class="form-table">
                <tr>
                    <th scope="row">API Key</th>
                    <td>
                        <input type="text" name="abuseipdb_api_key" value="<?php echo esc_attr(get_option('abuseipdb_api_key')); ?>" />
                    </td>
                </tr>
            </table>
            <?php submit_button(); ?>
        </form>
    </div>
    <?php
}

// Function to initialize the API key on plugin activation
function abuseipdb_activate() {
    add_option('abuseipdb_api_key', '');
}

// Function to remove the API key option on plugin deactivation
function abuseipdb_deactivate() {
    delete_option('abuseipdb_api_key');
}

// Function to report failed login attempts to AbuseIPDB
function report_failed_login($username, $error) {
    if (!is_plugin_active('all-in-one-wp-security-and-firewall/wp-security.php')) {
        return;
    }

    $ip = $_SERVER['REMOTE_ADDR'];

    if (hasFailedLoginInSecurityTable($ip)) {
        return;
    }

    $api_key = get_option('abuseipdb_api_key');
    $api_url = 'https://api.abuseipdb.com/api/v2/report';

    $data = array(
        'ip' => $ip,
        'categories' => '18,21',
        'comment' => "Failed login attempt for $username"
    );

    $headers = array('Key' => $api_key);

    $response = wp_remote_post($api_url, array(
        'headers' => $headers,
        'body' => http_build_query($data),
    ));

    if (!is_wp_error($response) && wp_remote_retrieve_response_code($response) == 200) {
        error_log('IP reported to AbuseIPDB: ' . $ip);
    }
}

// Function to check if an IP has a recent failed login in the All-in-One WP Security table
function hasFailedLoginInSecurityTable($ip) {
    global $wpdb;
    $table_name = $wpdb->prefix . 'aiowps_audit_log';

    if ($wpdb->get_var($wpdb->prepare("SHOW TABLES LIKE %s", $table_name)) != $table_name) {
        return false;
    }

    $result = $wpdb->get_row($wpdb->prepare("SELECT * FROM $table_name WHERE ip = %s AND event_type = 'failed_login' ORDER BY id DESC LIMIT 1", $ip));

    return $result && $result->created < time() - 900;
}
