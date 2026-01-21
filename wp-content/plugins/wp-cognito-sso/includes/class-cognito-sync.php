<?php

defined('ABSPATH') || exit;

use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;
use Aws\Exception\AwsException;

class WCSSO_Cognito_Sync {
    public static function init() {
        add_action('user_register', [__CLASS__, 'on_user_register'], 10, 1);
        add_action('profile_update', [__CLASS__, 'on_profile_update'], 10, 2);
    }

    public static function on_user_register($user_id) {
        $settings = wcsso_get_settings();
        if (empty($settings['sync_enabled']) || empty($settings['sync_on_user_register'])) {
            return;
        }
        self::sync_user($user_id);
    }

    public static function on_profile_update($user_id, $old_user_data) {
        $settings = wcsso_get_settings();
        if (empty($settings['sync_enabled']) || empty($settings['sync_on_profile_update'])) {
            return;
        }
        self::sync_user($user_id);
    }

    private static function sync_user($user_id) {
        if (!class_exists('Aws\\CognitoIdentityProvider\\CognitoIdentityProviderClient')) {
            wcsso_log('AWS SDK missing, sync skipped.');
            return;
        }

        $settings = wcsso_get_settings();
        $user = get_userdata($user_id);
        if (!$user) {
            return;
        }

        $aws_region = $settings['aws_region'];
        $access_key = $settings['aws_access_key'];
        $secret_key = $settings['aws_secret_key'];
        $user_pool_id = $settings['aws_user_pool_id'];

        if (!$aws_region || !$access_key || !$secret_key || !$user_pool_id) {
            wcsso_log('Cognito sync aborted: missing AWS config.');
            return;
        }

        $client = new CognitoIdentityProviderClient([
            'region' => $aws_region,
            'version' => '2016-04-18',
            'credentials' => [
                'key' => $access_key,
                'secret' => $secret_key,
            ],
        ]);

        $first_name = get_user_meta($user_id, 'first_name', true) ?? '';
        $last_name = get_user_meta($user_id, 'last_name', true) ?? '';
        $full_name = trim($first_name . ' ' . $last_name);
        if ($full_name === '') {
            $full_name = $user->display_name ?? '';
        }

        $email = $user->user_email;
        if (empty($email)) {
            wcsso_log('Cognito sync aborted: missing user email.');
            return;
        }

        $user_phone = get_user_meta($user_id, 'billing_phone', true) ?? '';
        $address = wcsso_get_user_address($user_id);

        $role_attribute = $settings['sync_role_attribute_name'] ?: 'custom:user_role';
        $primary_role = wcsso_get_primary_role($user_id) ?: $settings['default_wp_role'];

        $attributes = [
            ['Name' => 'name', 'Value' => $full_name],
            ['Name' => 'given_name', 'Value' => $first_name],
            ['Name' => 'family_name', 'Value' => $last_name],
            ['Name' => 'email', 'Value' => $email],
            ['Name' => 'email_verified', 'Value' => 'true'],
            ['Name' => 'phone_number', 'Value' => $user_phone],
            ['Name' => 'phone_number_verified', 'Value' => $user_phone ? 'true' : 'false'],
            ['Name' => 'address', 'Value' => $address],
            ['Name' => $role_attribute, 'Value' => $primary_role],
        ];

        $raw_pass = apply_filters('wcsso_raw_password_for_user_sync', null, $user_id);

        try {
            $client->adminUpdateUserAttributes([
                'UserPoolId' => $user_pool_id,
                'Username' => $user->user_login,
                'UserAttributes' => $attributes,
            ]);
            if (is_string($raw_pass) && $raw_pass !== '') {
                $client->adminSetUserPassword([
                    'UserPoolId' => $user_pool_id,
                    'Username' => $user->user_login,
                    'Password' => $raw_pass,
                    'Permanent' => true,
                ]);
            }
            do_action('wcsso_sync_success', $user_id, 'update', $attributes);
        } catch (AwsException $e) {
            $code = $e->getAwsErrorCode();
            if ($code === 'UserNotFoundException') {
                try {
                    $params = [
                        'UserPoolId' => $user_pool_id,
                        'Username' => $user->user_login,
                        'UserAttributes' => $attributes,
                    ];
                    $client->adminCreateUser($params);

                    if (is_string($raw_pass) && $raw_pass !== '') {
                        $client->adminSetUserPassword([
                            'UserPoolId' => $user_pool_id,
                            'Username' => $user->user_login,
                            'Password' => $raw_pass,
                            'Permanent' => true,
                        ]);
                    }
                    do_action('wcsso_sync_success', $user_id, 'create', $attributes);
                } catch (AwsException $e2) {
                    wcsso_log($e2->getMessage());
                    do_action('wcsso_sync_error', $user_id, 'create', $e2);
                }
            } else {
                wcsso_log($e->getMessage());
                do_action('wcsso_sync_error', $user_id, 'update', $e);
            }
        }
    }
}
