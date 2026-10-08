<?php

// Same login as the impossible level (OWASP Authentication Cheat Sheet):
//  - credentials only in a POST body, never in the URL query string
//  - anti-CSRF token on every attempt, so scripted replays are refused
//  - prepared statements and a constant time password check
//  - per-account failed login counter (users.failed_login / last_login):
//    after 3 failed logins the account is locked for 15 minutes
//  - one generic answer for an unknown user, a wrong password and a locked
//    account, so the page never says which one it was; no sleep()

$total_failed_login = 3;
$lockout_time       = 15;
$login_failed_html  = "<pre><br />Username and/or password incorrect.<br /><br />Alternatively, the account has been locked because of too many failed logins.<br />If this is the case, <em>please try again in {$lockout_time} minutes</em>.</pre>";

if( isset( $_GET[ 'Login' ] ) || isset( $_GET[ 'username' ] ) || isset( $_GET[ 'password' ] ) ) {
	// Credentials in the URL (old GET form or a replayed attack): refused,
	// nothing is checked against the database
	$html .= $login_failed_html;
}
elseif( isset( $_POST[ 'Login' ] ) && isset( $_POST[ 'username' ] ) && isset( $_POST[ 'password' ] ) ) {
	// Check Anti-CSRF token
	checkToken( isset( $_REQUEST[ 'user_token' ] ) ? $_REQUEST[ 'user_token' ] : null, isset( $_SESSION[ 'session_token' ] ) ? $_SESSION[ 'session_token' ] : null, 'index.php' );

	// Get input (plain strings only)
	$user = is_string( $_POST[ 'username' ] ) ? $_POST[ 'username' ] : '';
	$pass = is_string( $_POST[ 'password' ] ) ? $_POST[ 'password' ] : '';
	$pass = md5( $pass );

	$account_locked = false;

	// Check the database (Check user information)
	// (the lockout window is worked out by the database itself, so a PHP / MySQL
	// time zone difference can't make it expire early)
	$data = $db->prepare( 'SELECT user, password, avatar, failed_login, last_login, ( last_login > ( NOW() - INTERVAL ' . intval( $lockout_time ) . ' MINUTE ) ) AS in_lockout_window FROM users WHERE user = (:user) LIMIT 1;' );
	$data->bindParam( ':user', $user, PDO::PARAM_STR );
	$data->execute();
	$row = $data->fetch( PDO::FETCH_ASSOC );

	// Check to see if the user has been locked out
	if( ( $row !== false ) && ( intval( $row[ 'failed_login' ] ) >= $total_failed_login ) && ( intval( $row[ 'in_lockout_window' ] ) == 1 ) ) {
		$account_locked = true;
	}

	// Does the password match? (constant time compare)
	$valid = ( $row !== false ) && hash_equals( strtolower( (string) $row[ 'password' ] ), $pass );

	if( $valid && ( $account_locked == false ) ) {
		// Login successful
		$user_html    = htmlspecialchars( $row[ 'user' ], ENT_QUOTES, 'UTF-8' );
		$avatar       = htmlspecialchars( $row[ 'avatar' ], ENT_QUOTES, 'UTF-8' );
		$failed_login = intval( $row[ 'failed_login' ] );
		$html .= "<p>Welcome to the password protected area {$user_html}</p>";
		$html .= "<img src=\"{$avatar}\" />";

		// Had the account been locked out since last login?
		if( $failed_login >= $total_failed_login ) {
			$last_html = htmlspecialchars( (string) $row[ 'last_login' ], ENT_QUOTES, 'UTF-8' );
			$html .= "<p><em>Warning</em>: Someone might of been brute forcing your account.</p>";
			$html .= "<p>Number of login attempts: <em>{$failed_login}</em>.<br />Last login attempt was at: <em>{$last_html}</em>.</p>";
		}

		// Reset bad login count
		$data = $db->prepare( 'UPDATE users SET failed_login = 0 WHERE user = (:user) LIMIT 1;' );
		$data->bindParam( ':user', $user, PDO::PARAM_STR );
		$data->execute();
	}
	else {
		// Login failed: same feedback whatever the reason
		$html .= $login_failed_html;

		// Update bad login count
		$data = $db->prepare( 'UPDATE users SET failed_login = (failed_login + 1) WHERE user = (:user) LIMIT 1;' );
		$data->bindParam( ':user', $user, PDO::PARAM_STR );
		$data->execute();
	}

	// Set the last login time
	$data = $db->prepare( 'UPDATE users SET last_login = now() WHERE user = (:user) LIMIT 1;' );
	$data->bindParam( ':user', $user, PDO::PARAM_STR );
	$data->execute();
}

// Generate Anti-CSRF token
generateSessionToken();

?>
