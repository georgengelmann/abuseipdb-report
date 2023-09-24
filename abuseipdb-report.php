<?php
/**
 * Plugin Name: AbuseIPDB Report with All-in-One WP Security Integration
 * Description: Report failed login attempts to AbuseIPDB after checking if the All-in-One WP Security plugin is enabled and then checking the plugin's table.
 * Version: 1.0
 * Author: Georg Engelmann <mail@georg-engelmann.at>
 */

// Your AbuseIPDB API Key
$api_key = 'YOUR_API_KEY';

// AbuseIPDB API Endpoint
$api_url = 'https://api.abuseipdb.com/api/v2/report';

// WordPress Hook to capture failed login attempts
function report_failed_login($username, $error) {
    global $api_key, $api_url;

    // Check if the All-In-One WP Security plugin is active
    if (is_plugin_active('all-in-one-wp-security-and-firewall/wp-security.php')) {

        // Get the IP address of the failed login attempt
        $ip = $_SERVER['REMOTE_ADDR'];

        // Check if the IP address has already had a failed login attempt
        if (!hasFailedLoginInSecurityTable($ip, $wp_security_table_prefix)) {
            // Define the parameters for the AbuseIPDB report
            $data = array(
                'ip' => $ip,
                'categories' => '18,22',  // WordPress Brute Force and Web App Attack categories
                'comment' => "Failed login attempt for $username"
            );

            $headers = array(
                'Key' => $api_key,
            );

            // Send the report to AbuseIPDB using wp_remote_post
            $response = wp_remote_post($api_url, array(
                'headers' => $headers,
                'body' => http_build_query($data),
            ));

            if (!is_wp_error($response) && wp_remote_retrieve_response_code($response) == 200) {
                echo 'You have been reported.';
            }
        }
	}
}

// Hook into the wp_login_failed event
add_action('wp_login_failed', 'report_failed_login', 10, 2);

// Function to check if an IP has a failed login in the All-in-One WP Security table
function hasFailedLoginInSecurityTable($ip) {
    global $wpdb;
    $table_name = $wpdb->prefix . 'aiowps_audit_log'; // Change to the actual table name used by the plugin

    // Check if the table exists
    if ($wpdb->get_var("SHOW TABLES LIKE '$table_name'") == $table_name) {
        // Query the table to check if the IP has a failed login attempt
        $result = $wpdb->get_row($wpdb->prepare("SELECT * FROM $table_name WHERE ip = '%s' AND event_type = 'failed_login' ORDER BY id DESC LIMIT 1", $ip));
	if ($result->{'created'} < time() - 900) {
            return true; // IP has a recent failed login
        }
    }

    return false; // IP does not have a recent failed login
}
