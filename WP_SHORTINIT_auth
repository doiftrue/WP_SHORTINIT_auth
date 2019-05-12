<?php

// указываем, что нам нужен минимум от WP
define('SHORTINIT', true);

// подгружаем среду WordPress
require_once( $_SERVER['DOCUMENT_ROOT'] . '/wp/wp-load.php' );

// укороченная версия wp_hash из pluggable.php
function wp_hash( $data ){
	$salt = LOGGED_IN_KEY . LOGGED_IN_SALT;
	return hash_hmac('md5', $data, $salt);
}

function hash_token( $token ){
	if( function_exists( 'hash' ) )
		return hash( 'sha256', $token );
	else
		return sha1( $token );
}

function curr_user_can($capability){
	global $all_caps;
	return isset( $all_caps[$capability] ) && $all_caps[$capability];
}

function get_curr_user_can(){
	global $wpdb;
	$_options = $wpdb->get_results("SELECT `option_name`, `option_value` FROM $wpdb->options WHERE `option_name` IN ('siteurl', '".$wpdb->prefix."user_roles')", 'OBJECT_K');
	if(!$_options)
		return array( 'error', 'Опции не найдены' );

	$_c_hash = md5( $_options['siteurl']->option_value );
	if( !isset( $_COOKIE['wordpress_logged_in_'.$_c_hash] ) )
		return array( 'error', 'Кука отсутствует' );

	$cookie          = $_COOKIE['wordpress_logged_in_'.$_c_hash];
	$cookie_elements = explode('|', $cookie);
	if( count( $cookie_elements ) !== 4 )
		return array( 'error', 'Кука битая' );

	$username   = $cookie_elements[0];
	$expiration = $cookie_elements[1];
	$token      = $cookie_elements[2];
	$hmac       = $cookie_elements[3];

	if( $expiration < time() )
		return array( 'error', 'Время сессии истекло' );

	$user = $wpdb->get_row( $wpdb->prepare("SELECT * FROM $wpdb->users WHERE `user_login`=%s", $username) , 'OBJECT' );
	if( ! $user )
		return array( 'error', 'Нет такого юзера' );

	$pass_frag = substr($user->user_pass, 8, 4);
	$key       = wp_hash( $username . '|' . $pass_frag . '|' . $expiration . '|' . $token );
	$algo      = function_exists( 'hash' ) ? 'sha256' : 'sha1';
	$hash      = hash_hmac( $algo, $username . '|' . $expiration . '|' . $token, $key );
	if( ! hash_equals( $hash, $hmac ) )
		return array( 'error', 'Хэш не эквивалентен' );

	$user_options = $wpdb->get_results("SELECT `meta_key` ,`meta_value` FROM $wpdb->usermeta WHERE (`user_id`=".$user->ID.") AND (`meta_key` IN ('session_tokens', '".$wpdb->prefix."capabilities') )", OBJECT_K );
	if(!$user_options)
		return array( 'error', 'Юзер опции не установлены' );

	$sessions = unserialize($user_options['session_tokens']->meta_value);
	$verifier = hash_token( $token );
	if( !isset( $sessions[ $verifier ] ) )
		return array( 'error', 'Токен авторизации отсутствует' );

	if( $sessions[$verifier]['expiration'] < time() )
		return array( 'error', 'Время сессии истекло' );

	$role_caps = unserialize( $_options[ $wpdb->prefix.'user_roles' ]->option_value );
	$user_caps = unserialize( $user_options[ $wpdb->prefix.'capabilities' ]->meta_value );
	$all_caps  = array();
	foreach($user_caps as $key => $value){
		if( isset($role_caps[$key]) && $value )
			$all_caps = array_merge( $all_caps, $role_caps[$key]['capabilities'] );
		else
			$all_caps[$key] = $value;
	}
	return array( 'success', $all_caps );
}
