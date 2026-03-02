<?php

defined('ABSPATH') || exit;

class WCSSO_Cognito_Migration_Endpoint
{
    const ROUTE_NAMESPACE = 'cognito-migrate/v1';
    const ROUTE_VERIFY = '/verify';

    public static function init()
    {
        add_action('rest_api_init', [__CLASS__, 'register_routes']);
    }

    public static function register_routes()
    {
        register_rest_route(self::ROUTE_NAMESPACE, self::ROUTE_VERIFY, [
            'methods' => 'POST',
            'callback' => [__CLASS__, 'handle_verify'],
            'permission_callback' => [__CLASS__, 'permission_check'],
            'args' => [
                'username' => [
                    'required' => true,
                    'type' => 'string',
                ],
                'password' => [
                    'required' => true,
                    'type' => 'string',
                ],
            ],
        ]);
    }

    public static function permission_check(\WP_REST_Request $request)
    {
        $secret = self::get_shared_secret();
        if (!$secret) {
            return new \WP_Error('cognito_migrate_secret_missing', 'Migration secret not configured.', ['status' => 500]);
        }

        $timestamp = $request->get_header('x-cognito-migrate-timestamp');
        $signature = $request->get_header('x-cognito-migrate-signature');

        if (!$timestamp || !$signature) {
            return new \WP_Error('cognito_migrate_auth_missing', 'Missing auth headers.', ['status' => 401]);
        }

        if (!ctype_digit((string) $timestamp)) {
            return new \WP_Error('cognito_migrate_bad_timestamp', 'Invalid timestamp.', ['status' => 401]);
        }

        $ts = (int) $timestamp;
        $now = time();
        if ($ts < ($now - 300) || $ts > ($now + 300)) {
            return new \WP_Error('cognito_migrate_ts_out_of_range', 'Timestamp out of range.', ['status' => 401]);
        }

        $raw_body = $request->get_body();
        $payload = $timestamp . '.' . $raw_body;
        $expected = hash_hmac('sha256', $payload, $secret);
        $provided = strtolower(trim((string) $signature));

        if (!hash_equals($expected, $provided)) {
            return new \WP_Error('cognito_migrate_sig_invalid', 'Invalid signature.', ['status' => 401]);
        }

        return true;
    }

    public static function handle_verify(\WP_REST_Request $request)
    {
        $username = (string) $request->get_param('username');
        $password = (string) $request->get_param('password');

        $user = wp_authenticate($username, $password);
        if (is_wp_error($user)) {
            return new \WP_REST_Response([
                'ok' => false,
            ], 401);
        }

        return new \WP_REST_Response([
            'ok' => true,
            'user' => [
                'id' => (int) $user->ID,
                'user_login' => (string) $user->user_login,
                'email' => (string) $user->user_email,
                'display_name' => (string) $user->display_name,
            ],
        ], 200);
    }

    private static function get_shared_secret()
    {
        $settings_secret = wcsso_get_setting('migration_shared_secret', '');
        if (is_string($settings_secret) && $settings_secret !== '') {
            return $settings_secret;
        }

        if (defined('COGNITO_MIGRATION_SHARED_SECRET') && COGNITO_MIGRATION_SHARED_SECRET) {
            return COGNITO_MIGRATION_SHARED_SECRET;
        }

        return null;
    }
}
