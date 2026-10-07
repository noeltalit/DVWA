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

	// Lock an account out for a while after too many failed logins
	$total_failed_login = 3;
	$lockout_time       = 15;
	$account_locked     = false;

	// Check the database (Check user information)
	$data = $db->prepare( 'SELECT failed_login, last_login FROM users WHERE user = (:user) LIMIT 1;' );
	$data->bindParam( ':user', $user, PDO::PARAM_STR );
	$data->execute();
	$row = $data->fetch();

	// Check to see if the user has been locked out.
	if( ( $data->rowCount() == 1 ) && ( $row[ 'failed_login' ] >= $total_failed_login ) ) {
		// Calculate when the user would be allowed to login again
		$last_login = strtotime( $row[ 'last_login' ] );
		$timeout    = $last_login + ( $lockout_time * 60 );

		// Check to see if enough time has passed, if it hasn't locked the account
		if( time() < $timeout ) {
			$account_locked = true;
		}
	}

	// Check the database (if username matches the password)
	$data = $db->prepare( 'SELECT * FROM users WHERE user = (:user) AND password = (:password) LIMIT 1;' );
	$data->bindParam( ':user', $user, PDO::PARAM_STR );
	$data->bindParam( ':password', $pass, PDO::PARAM_STR );
	$data->execute();
	$row = $data->fetch();

	if( ( $data->rowCount() == 1 ) && ( $account_locked == false ) ) {
		// Get users details
		$avatar = htmlspecialchars( $row[ 'avatar' ], ENT_QUOTES, 'UTF-8' );
		$user_html = htmlspecialchars( $row[ 'user' ], ENT_QUOTES, 'UTF-8' );

		// Login successful
		$html .= "<p>Welcome to the password protected area {$user_html}</p>";
		$html .= "<img src=\"{$avatar}\" />";

		// Reset bad login count
		$data = $db->prepare( 'UPDATE users SET failed_login = "0" WHERE user = (:user) LIMIT 1;' );
		$data->bindParam( ':user', $user, PDO::PARAM_STR );
		$data->execute();
	}
	else {
		// Login failed
		$html .= "<pre><br />Username and/or password incorrect.<br /><br />Alternatively, the account has been locked because of too many failed logins.<br />If this is the case, <em>please try again in {$lockout_time} minutes</em>.</pre>";

		// Update bad login count
		$data = $db->prepare( 'UPDATE users SET failed_login = (failed_login + 1) WHERE user = (:user) LIMIT 1;' );
		$data->bindParam( ':user', $user, PDO::PARAM_STR );
		$data->execute();
	}

	// Set the last login time
	$data = $db->prepare( 'UPDATE users SET last_login = now() WHERE user = (:user) LIMIT 1;' );
	$data->bindParam( ':user', $user, PDO::PARAM_STR );
	$data->execute();

	((is_null($___mysqli_res = mysqli_close($GLOBALS["___mysqli_ston"]))) ? false : $___mysqli_res);
}

// Generate Anti-CSRF token
generateSessionToken();

?>
