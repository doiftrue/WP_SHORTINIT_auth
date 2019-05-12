<?php

// указываем, что нам нужен минимум от WP
define('SHORTINIT', true);

// подгружаем среду WordPress
require_once( $_SERVER['DOCUMENT_ROOT'] . '/wp/wp-load.php' );

// укороченная версия wp_hash из pluggable.php
function wp_hash($data) {
	$salt = LOGGED_IN_KEY . LOGGED_IN_SALT;
	return hash_hmac('md5', $data, $salt);
}

function hash_token( $token ) {
	if ( function_exists( 'hash' ) ) {
		return hash( 'sha256', $token );
	} else {
		return sha1( $token );
	}
}

global $wpdb;

// получаем значение siteurl и список ролей из БД, неудачно - прерываем выполнение скрипта
$_options = $wpdb->get_results("SELECT `option_name`, `option_value` FROM $wpdb->options WHERE `option_name` IN ('siteurl', '".$wpdb->prefix."user_roles')", 'OBJECT_K');
if (!$_options) exit;

// получаем md5 хеш для siteurl - он формирует ключ куки
$_c_hash = md5( $_options['siteurl']->option_value );

if ( !isset( $_COOKIE['wordpress_logged_in_'.$_c_hash] ) ) exit;

// получаем параметр, разбиваем на элементы
$cookie = $_COOKIE['wordpress_logged_in_'.$_c_hash];
$cookie_elements = explode('|', $cookie);

// кол-во элементов = 4, если нет - параметр куки поврежден, прерываем скрипт
if ( count( $cookie_elements ) !== 4 ) exit;
list( $username, $expiration, $token, $hmac ) = $cookie_elements;

// проверяем время жизни куки, если истекло - прерываем скрипт
if ( $expiration &lt; time() ) exit; 

// получаем данные о пользователе из БД по логину, не удалось - прерываем скрипт
$user = $wpdb->get_row( $wpdb->prepare("SELECT * FROM $wpdb->users WHERE `user_login`=%s", $username) , 'OBJECT' );
if ( ! $user ) exit;

$pass_frag = substr($user->user_pass, 8, 4);
$key = wp_hash( $username . '|' . $pass_frag . '|' . $expiration . '|' . $token );

$algo = function_exists( 'hash' ) ? 'sha256' : 'sha1';
$hash = hash_hmac( $algo, $username . '|' . $expiration . '|' . $token, $key );
// хеш код из куки не совпал с вычисленным - прерываем скрипт
if ( ! hash_equals( $hash, $hmac ) ) exit;

// проверяем сессию
// получаем сессии пользователя и доп. права по user ID из usermeta, не получили - прерываем скрипт
$user_options = $wpdb->get_results("SELECT `meta_key` ,`meta_value` FROM $wpdb->usermeta WHERE (`user_id`=".$user->ID.") AND (`meta_key` IN ('session_tokens', '".$wpdb->prefix."capabilities') )", OBJECT_K );
if (!$user_options) exit;

$sessions = unserialize($user_options['session_tokens']->meta_value);
$verifier = hash_token( $token );

// сессия не найдена или устарела - прерываем скрипт
if ( isset( $sessions[ $verifier ] ) ) {
	if ( $sessions[$verifier]['expiration'] &lt; time() ) exit; 
} else exit;

// наборы прав для ролей и пользователя
$role_caps = unserialize( $_options[ $wpdb->prefix.'user_roles' ]->option_value );
$user_caps = unserialize( $user_options[ $wpdb->prefix.'capabilities' ]->meta_value );
$all_caps = array();
// формируем общий набор прав пользователя
foreach ($user_caps as $key => $value){
	//$key есть в наборе ролей - значит, это роль 
	if ( isset($role_caps[$key]) && $value ) 
		$all_caps = array_merge( $all_caps, $role_caps[$key]['capabilities'] );
	// это ключ-право пользователя
	else
		$all_caps[$key] = $value;
}

// аналог current_user_can()
function curr_user_can($capability){
	global $all_caps;
	return isset( $all_caps[$capability] ) && $all_caps[$capability];
}

// все проверки пройдены, можно выполнять запросы

// массив прав текущего пользователя
print_r( $all_caps );
