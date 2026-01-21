<?php

defined('ABSPATH') || exit;

class WCSSO_User_Provisioner {
    public static function create_or_update($claims) {
        $settings = wcsso_get_settings();
        $email_key = $settings['email_claim_key'];
        $username_key = $settings['username_claim_key'];
        $display_key = $settings['display_name_claim_key'];

        $email = $claims[$email_key] ?? '';
        if (empty($email) || !is_email($email)) {
            return new WP_Error('wcsso_missing_email', 'No email returned by identity provider.');
        }

        $user = get_user_by('email', $email);
        $is_new = false;

        $first_name = $claims['given_name'] ?? '';
        $last_name = $claims['family_name'] ?? '';
        $display_name = $claims[$display_key] ?? '';

        if (!$user) {
            $username_claim = $claims[$username_key] ?? '';
            if ($username_claim === '' && !empty($claims['preferred_username'])) {
                $username_claim = $claims['preferred_username'];
            }
            if ($username_claim === '' && $first_name !== '') {
                $username_claim = $first_name . ($last_name ? '-' . $last_name : '');
            }
            if ($username_claim === '') {
                $username_claim = sanitize_user(strstr($email, '@', true), true);
            }

            $username = wcsso_generate_unique_username($username_claim);
            $password = wp_generate_password(20, true, true);

            $user_id = wp_create_user($username, $password, $email);
            if (is_wp_error($user_id)) {
                return $user_id;
            }

            $user = get_user_by('id', $user_id);
            $is_new = true;
        }

        if ($user) {
            $updates = [
                'ID' => $user->ID,
            ];

            if ($first_name !== '') {
                $updates['first_name'] = sanitize_text_field($first_name);
            }
            if ($last_name !== '') {
                $updates['last_name'] = sanitize_text_field($last_name);
            }
            if ($display_name !== '') {
                $updates['display_name'] = sanitize_text_field($display_name);
                $updates['nickname'] = sanitize_text_field($display_name);
            }

            if (count($updates) > 1) {
                wp_update_user($updates);
            }

            self::apply_role_mapping($user, $claims);

            if ($is_new) {
                do_action('wcsso_user_created', $user->ID, $claims);
            } else {
                do_action('wcsso_user_updated', $user->ID, $claims);
            }

            return $user->ID;
        }

        return new WP_Error('wcsso_user_error', 'Unable to provision user.');
    }

    private static function apply_role_mapping(WP_User $user, $claims) {
        $settings = wcsso_get_settings();
        $claim_key = $settings['role_claim_key'];
        $claim_value = $claims[$claim_key] ?? '';

        $role_map = is_array($settings['role_mapping']) ? $settings['role_mapping'] : [];
        $mapped_role = $role_map[$claim_value] ?? $settings['default_wp_role'];
        $mapped_role = apply_filters('wcsso_mapped_wp_role', $mapped_role, $claim_value, $claims);

        $current_role = wcsso_get_primary_role($user->ID);
        $should_set = true;
        if (!empty($settings['only_set_role_if_current_role_is_default']) && $current_role !== '') {
            $should_set = ($current_role === $settings['default_wp_role']);
        }

        if ($mapped_role && $should_set) {
            $user->set_role($mapped_role);
        }

        do_action('wcsso_role_mapped', $user->ID, $claim_value, $mapped_role);
    }
}
