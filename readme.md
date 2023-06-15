=== Ade Woo API Authentication ===
Contributors: biggidroid
Tags: ade-woo-api-auth, rest api, api, woo api, api auth, rest auth, simple auth, simple authentication, authentication, auth, rest, restful, restful api, restful authentication, restful auth, restful api
Requires at least: 6.0
Tested up to: 6.2
Requires PHP: 7.3
Stable tag: 7.7.2
License: GPLv3
License URI: https://www.gnu.org/licenses/gpl-3.0.html

This plugin allow you to authenticate your API request with woo-commerce authentication.

== Description ==

This plugin allow you to authenticate your API request with woo-commerce authentication.

== Installation ==

1. Upload the plugin files to the `/wp-content/plugins/ade-woo-api-auth` directory, or install the plugin through the WordPress plugins screen directly.
2. Activate the plugin through the 'Plugins' screen in WordPress
3. See more details below.

```php

//add the following code in your theme's functions.php file or in your plugin file.

require_once WP_PLUGIN_DIR . '/ade-woo-api-auth/ade-woo-api-auth.php'; //include the plugin file

//declare an api endpoint
add_action('rest_api_init', function () {
	register_rest_route('ade/custom', '/get_post_ade', array(
		'methods' => 'GET',
		'callback' => 'get_post_ade',
		'permission_callback' => 'ade_oauth_authentication' //add this line to authenticate your api request
	));
});

//declare a callback function
function get_post_ade()
{
	return new WP_REST_Response([
		'posts' => 'hello world'
	]);
}

//add the following code in your theme's functions.php file or in your plugin file. If you want to authenticate your api request with custom authentication.

//We have way to authenticate your api request. You can use any one of the following method.

//Method 1:
 ade_woo_auth() //This function is used to authenticate rest api request with query string authentication method on ssl

//Method 2:
 ade_woo_auth_no_ssl() //This function is used to authenticate rest api request with query string authentication method on non-ssl

//Method 3:
 ade_oauth_authentication() //This function is used to authenticate rest api request with oauth authentication method both ssl and non ssl

```

== Changelog ==

= 1.0.0 =

- Initial release

== Upgrade Notice ==

= 1.0.0 =

- Initial release
