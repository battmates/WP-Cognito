<?php

defined('ABSPATH') || exit;

class WCSSO_JWT {
    public static function decode($jwt, $options = []) {
        $parts = explode('.', (string) $jwt);
        if (count($parts) !== 3) {
            return new WP_Error('wcsso_invalid_jwt', 'Invalid JWT format.');
        }

        $header = json_decode(self::base64url_decode($parts[0]), true);
        $payload = json_decode(self::base64url_decode($parts[1]), true);
        $signature = self::base64url_decode($parts[2]);

        if (!is_array($header) || !is_array($payload)) {
            return new WP_Error('wcsso_invalid_jwt', 'Invalid JWT payload.');
        }

        $verify = !empty($options['verify']);
        if ($verify) {
            $verify_result = self::verify($parts[0], $parts[1], $signature, $header, $payload, $options);
            if (is_wp_error($verify_result)) {
                return $verify_result;
            }
        }

        return $payload;
    }

    private static function verify($encoded_header, $encoded_payload, $signature, $header, $payload, $options) {
        if (empty($header['alg']) || empty($header['kid'])) {
            return new WP_Error('wcsso_invalid_jwt', 'Missing JWT header fields.');
        }

        $client_id = $options['client_id'] ?? '';
        if ($client_id !== '') {
            $aud = $payload['aud'] ?? '';
            if (is_array($aud)) {
                if (!in_array($client_id, $aud, true)) {
                    return new WP_Error('wcsso_invalid_jwt', 'JWT audience mismatch.');
                }
            } elseif ($aud !== '' && $aud !== $client_id) {
                return new WP_Error('wcsso_invalid_jwt', 'JWT audience mismatch.');
            }
        }

        if (!empty($payload['exp']) && time() >= (int) $payload['exp']) {
            return new WP_Error('wcsso_invalid_jwt', 'JWT is expired.');
        }

        $jwks_url = self::resolve_jwks_url($payload, $options);
        if (!$jwks_url) {
            return new WP_Error('wcsso_invalid_jwt', 'Unable to resolve JWKS URL.');
        }

        $jwks = self::get_jwks($jwks_url);
        if (is_wp_error($jwks)) {
            return $jwks;
        }

        $key = self::find_jwk($jwks, $header['kid']);
        if (!$key) {
            return new WP_Error('wcsso_invalid_jwt', 'JWT key not found.');
        }

        $pem = self::jwk_to_pem($key);
        if (!$pem) {
            return new WP_Error('wcsso_invalid_jwt', 'Unable to construct key for JWT verification.');
        }

        if (!function_exists('openssl_verify')) {
            return new WP_Error('wcsso_invalid_jwt', 'OpenSSL not available for JWT verification.');
        }

        $data = $encoded_header . '.' . $encoded_payload;
        $ok = openssl_verify($data, $signature, $pem, OPENSSL_ALGO_SHA256);
        if ($ok !== 1) {
            return new WP_Error('wcsso_invalid_jwt', 'JWT signature verification failed.');
        }

        return true;
    }

    private static function resolve_jwks_url($payload, $options) {
        if (!empty($payload['iss'])) {
            return rtrim($payload['iss'], '/') . '/.well-known/jwks.json';
        }
        if (!empty($options['cognito_domain'])) {
            return 'https://' . trim($options['cognito_domain']) . '/.well-known/jwks.json';
        }
        return '';
    }

    private static function get_jwks($jwks_url) {
        $cache_key = 'wcsso_jwks_' . md5($jwks_url);
        $cached = get_transient($cache_key);
        if ($cached) {
            return $cached;
        }

        $response = wp_remote_get($jwks_url, ['timeout' => 10]);
        if (is_wp_error($response)) {
            return $response;
        }

        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);
        if (empty($data['keys'])) {
            return new WP_Error('wcsso_invalid_jwks', 'Invalid JWKS response.');
        }

        set_transient($cache_key, $data, 6 * HOUR_IN_SECONDS);
        return $data;
    }

    private static function find_jwk($jwks, $kid) {
        if (empty($jwks['keys']) || !is_array($jwks['keys'])) {
            return null;
        }
        foreach ($jwks['keys'] as $key) {
            if (!empty($key['kid']) && $key['kid'] === $kid) {
                return $key;
            }
        }
        return null;
    }

    private static function jwk_to_pem($jwk) {
        if (empty($jwk['n']) || empty($jwk['e'])) {
            return null;
        }

        $modulus = self::base64url_decode($jwk['n']);
        $exponent = self::base64url_decode($jwk['e']);

        $modulus = "\x02" . self::encode_length(strlen($modulus)) . $modulus;
        $exponent = "\x02" . self::encode_length(strlen($exponent)) . $exponent;

        $sequence = "\x30" . self::encode_length(strlen($modulus . $exponent)) . $modulus . $exponent;

        $bitstring = "\x03" . self::encode_length(strlen($sequence) + 1) . "\x00" . $sequence;

        $rsa_oid = "\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01\x05\x00";
        $public_key = "\x30" . self::encode_length(strlen($rsa_oid . $bitstring)) . $rsa_oid . $bitstring;

        $pem = "-----BEGIN PUBLIC KEY-----\n";
        $pem .= chunk_split(base64_encode($public_key), 64, "\n");
        $pem .= "-----END PUBLIC KEY-----\n";

        return $pem;
    }

    private static function encode_length($length) {
        if ($length <= 0x7F) {
            return chr($length);
        }
        $temp = ltrim(pack('N', $length), "\x00");
        return chr(0x80 | strlen($temp)) . $temp;
    }

    private static function base64url_decode($data) {
        $remainder = strlen($data) % 4;
        if ($remainder) {
            $data .= str_repeat('=', 4 - $remainder);
        }
        return base64_decode(strtr($data, '-_', '+/'));
    }
}
