<?php

if( isset( $_GET[ 'Login' ] ) ) {
	// Check Anti-CSRF token
	checkToken( isset( $_REQUEST[ 'user_token' ] ) ? $_REQUEST[ 'user_token' ] : null, isset( $_SESSION[ 'session_token' ] ) ? $_SESSION[ 'session_token' ] : null, 'index.php' );

	// Sanitise username input
	$user = isset( $_GET[ 'username' ] ) ? (is_string( $_GET[ 'username' ] ) ? $_GET[ 'username' ] : '') : '';
	$user = stripslashes( $user );
	$user = mysqli_real_escape_string( $GLOBALS["___mysqli_ston"], $user );

	// Sanitise password input
	$pass = isset( $_GET[ 'password' ] ) ? (is_string( $_GET[ 'password' ] ) ? $_GET[ 'password' ] : '') : '';
	$pass = stripslashes( $pass );
	$pass = mysqli_real_escape_string( $GLOBALS["___mysqli_ston"], $pass );
	$pass = md5( $pass );

	// Throttle guessing. After a failed login the account has to wait before
	// another attempt is even checked: 2 seconds for the first few failures
	// (enough for typos), then doubling up to 15 minutes. Attempts made too
	// soon are rejected without looking at the password, so an automated
	// guessing run gets nowhere, while a real user can simply retry.
	$throttled = false;
	$data = $db->prepare( 'SELECT failed_login, TIMESTAMPDIFF( SECOND, last_login, NOW() ) AS since_last FROM users WHERE user = (:user) LIMIT 1;' );
	$data->bindParam( ':user', $user, PDO::PARAM_STR );
	$data->execute();
	$row = $data->fetch();

	if( ( $data->rowCount() == 1 ) && ( $row[ 'failed_login' ] > 0 ) ) {
		$failures = intval( $row[ 'failed_login' ] );
		$wait     = ( $failures <= 3 ) ? 2 : min( pow( 2, $failures - 2 ), 15 * 60 );
		if( $row[ 'since_last' ] === null || intval( $row[ 'since_last' ] ) < $wait ) {
			$throttled = true;
		}
	}

	$logged_in = false;
	if( !$throttled ) {
		// Check the database (if username matches the password)
		$data = $db->prepare( 'SELECT * FROM users WHERE user = (:user) AND password = (:password) LIMIT 1;' );
		$data->bindParam( ':user', $user, PDO::PARAM_STR );
		$data->bindParam( ':password', $pass, PDO::PARAM_STR );
		$data->execute();
		$row = $data->fetch();

		if( $data->rowCount() == 1 ) {
			$logged_in = true;

			// Get users details
			$avatar = htmlspecialchars( $row[ 'avatar' ], ENT_QUOTES, 'UTF-8' );
			$user_html = htmlspecialchars( $row[ 'user' ], ENT_QUOTES, 'UTF-8' );

			// Login successful
			$html .= "<p>Welcome to the password protected area {$user_html}</p>";
			$html .= "<img src=\"{$avatar}\" />";

			// Reset bad login count
			$data = $db->prepare( 'UPDATE users SET failed_login = 0, last_login = NOW() WHERE user = (:user) LIMIT 1;' );
			$data->bindParam( ':user', $user, PDO::PARAM_STR );
			$data->execute();
		}
		else {
			// Count the failure and start the wait
			$data = $db->prepare( 'UPDATE users SET failed_login = (failed_login + 1), last_login = NOW() WHERE user = (:user) LIMIT 1;' );
			$data->bindParam( ':user', $user, PDO::PARAM_STR );
			$data->execute();
		}
	}

	if( !$logged_in ) {
		// Same answer whether the password was wrong or the attempt came too soon
		$html .= "<pre><br />Username and/or password incorrect.<br /><br />After a failed login the account has to wait a little before it can be tried again.</pre>";
	}

	((is_null($___mysqli_res = mysqli_close($GLOBALS["___mysqli_ston"]))) ? false : $___mysqli_res);
}

// Generate Anti-CSRF token
generateSessionToken();

?>
