<?php

if( isset( $_GET[ 'Login' ] ) ) {
	require_once DVWA_WEB_PAGE_TO_ROOT . 'vulnerabilities/brute/login_guard.inc.php';

	// Get username and password (plain strings only)
	$user = ( isset( $_GET[ 'username' ] ) && is_string( $_GET[ 'username' ] ) ) ? $_GET[ 'username' ] : '';
	$pass = ( isset( $_GET[ 'password' ] ) && is_string( $_GET[ 'password' ] ) ) ? $_GET[ 'password' ] : '';

	// Prepared statement lookup, constant time hash comparison and a
	// per-account failed login counter: after a failed login the account
	// cools down, after 3 failures it is locked for 15 minutes. While it is
	// locked the password isn't checked at all, so a guessing run only ever
	// gets the "account locked" page.
	$result = bruteLoginAttempt( $db, 'medium', $user, $pass );
	$html  .= bruteLoginHtml( $result );

	((is_null($___mysqli_res = mysqli_close($GLOBALS["___mysqli_ston"]))) ? false : $___mysqli_res);
}

?>
