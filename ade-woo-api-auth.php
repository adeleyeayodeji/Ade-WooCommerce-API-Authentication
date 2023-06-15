<?php

/**
 * Plugin Name: Ade Woo API Auth
 * Plugin URI:  https://www.adeleyeayodeji.com/
 * Author:      Adeleye Ayodeji
 * Author URI:  https://www.adeleyeayodeji.com/
 * Description: This plugin allow you to authenticate your woocommerce API request
 * Version:     0.1.0
 * License:     GPL-2.0+
 * License URL: http://www.gnu.org/licenses/gpl-2.0.txt
 * text-domain: ade-woo-api-auth
 */
//security
if (!defined('ABSPATH')) {
    exit;
}

//define plugin version
define('ADE_WOO_API_AUTH_VERSION', '0.1.0');
//plugin file
define('ADE_WOO_API_AUTH_FILE', __FILE__);
//plugin folder path
define('ADE_WOO_API_AUTH_PATH', plugin_dir_path(__FILE__));
//plugin folder url
define('ADE_WOO_API_AUTH_URL', plugin_dir_url(__FILE__));

require_once ADE_WOO_API_AUTH_PATH . 'inc/core.php';

//initialize the class
$ADE_WOO_API_Authentication = new ADE_WOO_API_Authentication();
//decalre global variables
$GLOBALS['ADE_WOO_API_Authentication'] = $ADE_WOO_API_Authentication;

//check if fucntion exist
if (!function_exists('ade_woo_auth')) {
    /**
     * Function ade_woo_auth()
     * 
     * @description: This function is used to authenticate rest api request with query string authentication method on ssl
     * 
     * @return mixed
     */
    function ade_woo_auth()
    {
        $adewooauth = new ADE_WOO_API_Authentication();
        return $adewooauth->authenticate();
    }
}

//ade_woo_auth_no_ssl
if (!function_exists('ade_woo_auth_no_ssl')) {
    /**
     * Function ade_woo_auth_no_ssl()
     * 
     * @description: This function is used to authenticate rest api request with query string authentication method on non ssl
     * 
     * @return mixed
     */
    function ade_woo_auth_no_ssl()
    {
        $adewooauth = new ADE_WOO_API_Authentication();
        return $adewooauth->authenticate_basic_no_ssl();
    }
}

//ade_oauth_authentication
if (!function_exists('ade_oauth_authentication')) {
    /**
     * Function ade_oauth_authentication()
     * 
     * @description: This function is used to authenticate rest api request with oauth authentication method both ssl and non ssl
     * 
     * @return mixed
     */
    function ade_oauth_authentication()
    {
        $adewooauth = new ADE_WOO_API_Authentication();
        return $adewooauth->oauth_authentication_();
    }
}
