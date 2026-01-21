# WP-Cognito
A Wordpress plugin to authenticate via the AWS Cognito Hosted UI

## Install

1. Copy the plugin to `wp-content/plugins/wp-cognito-sso`.
2. Install dependencies:

```bash
cd wp-content/plugins/wp-cognito-sso
composer install --no-dev --optimize-autoloader
```

3. Activate the plugin in WordPress.

## Usage

1. Go to Settings → Cognito SSO.
2. Configure Cognito Hosted UI settings (domain, client ID/secret, scope, redirect path).
3. In Cognito, allow the callback URL shown on the settings page.
4. Enable "Hosted UI login" and optionally "Auto redirect".
5. Configure logout redirect path if you want Cognito logout on WP logout.
6. Configure user provisioning claim keys and role mapping.
7. Optional: enable WP → Cognito sync and provide AWS credentials + user pool ID.

Notes:
- This plugin uses the Amazon AWS SDK which can be installed via Composer.
- The callback endpoint is the redirect path (default `/cognito-login`).
- Auto redirect excludes wp-admin, wp-login.php, REST/AJAX, and any excluded paths.
- JWT verification is on by default; disable only if you cannot fetch JWKS.
