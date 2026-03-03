<?php

defined('ABSPATH') || exit;

class WCSSO_Cognito_Migration_Endpoint
{
    const ROUTE_NAMESPACE = 'cognito-migrate/v1';
    const ROUTE_VERIFY = '/verify';
    const ROUTE_LOOKUP = '/lookup';

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

        register_rest_route(self::ROUTE_NAMESPACE, self::ROUTE_LOOKUP, [
            'methods' => 'POST',
            'callback' => [__CLASS__, 'handle_lookup'],
            'permission_callback' => [__CLASS__, 'permission_check'],
            'args' => [
                'username' => [
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
        $identifier = trim((string) $request->get_param('username'));
        $password = (string) $request->get_param('password');

        $user = self::authenticate_by_username_or_email($identifier, $password);
        if (is_wp_error($user)) {
            return new \WP_REST_Response([
                'ok' => false,
            ], 401);
        }

        return new \WP_REST_Response([
            'ok' => true,
            'user' => self::build_user_payload($user),
        ], 200);
    }

    public static function handle_lookup(\WP_REST_Request $request)
    {
        $identifier = trim((string) $request->get_param('username'));
        $user = self::find_user_by_identifier($identifier);

        if (!($user instanceof \WP_User)) {
            return new \WP_REST_Response([
                'ok' => false,
            ], 404);
        }

        return new \WP_REST_Response([
            'ok' => true,
            'user' => self::build_user_payload($user),
        ], 200);
    }

    private static function authenticate_by_username_or_email($identifier, $password)
    {
        // First, attempt native WP auth. This already supports email in standard installs.
        $user = wp_authenticate($identifier, $password);
        if (!is_wp_error($user)) {
            return $user;
        }

        // Explicit fallback: if identifier looks like an email, resolve the user and
        // authenticate with the canonical login to avoid site-specific auth hook changes.
        if (is_email($identifier)) {
            $email = sanitize_email($identifier);
            $email_user = get_user_by('email', $email);
            if ($email_user instanceof \WP_User) {
                return wp_authenticate($email_user->user_login, $password);
            }
        }

        return $user;
    }

    private static function find_user_by_identifier($identifier)
    {
        if ($identifier === '') {
            return null;
        }

        if (is_email($identifier)) {
            $email = sanitize_email($identifier);
            $email_user = get_user_by('email', $email);
            if ($email_user instanceof \WP_User) {
                return $email_user;
            }
        }

        $user_login = sanitize_user($identifier, true);
        if ($user_login !== '') {
            $login_user = get_user_by('login', $user_login);
            if ($login_user instanceof \WP_User) {
                return $login_user;
            }
        }

        return null;
    }

    private static function build_user_payload(\WP_User $user)
    {
        return [
            'id' => (int) $user->ID,
            'user_login' => (string) $user->user_login,
            'email' => (string) $user->user_email,
            'display_name' => (string) $user->display_name,
            'first_name' => (string) get_user_meta($user->ID, 'first_name', true),
            'last_name' => (string) get_user_meta($user->ID, 'last_name', true),
        ];
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
