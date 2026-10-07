<?php

if( isset( $_GET[ 'Change' ] ) ) {
	// Check Anti-CSRF token, a forged cross-site request can't know it
	checkToken( isset( $_REQUEST[ 'user_token' ] ) ? $_REQUEST[ 'user_token' ] : null, isset( $_SESSION[ 'session_token' ] ) ? $_SESSION[ 'session_token' ] : null, 'index.php' );

	// Get input
	$pass_new  = isset( $_GET[ 'password_new' ] ) ? (is_string( $_GET[ 'password_new' ] ) ? $_GET[ 'password_new' ] : '') : '';
	$pass_conf = isset( $_GET[ 'password_conf' ] ) ? (is_string( $_GET[ 'password_conf' ] ) ? $_GET[ 'password_conf' ] : '') : '';

	// Do the passwords match?
	if( $pass_new === $pass_conf ) {
		// They do!
		$pass_new = mysqli_real_escape_string( $GLOBALS["___mysqli_ston"], $pass_new );
		$pass_new = md5( $pass_new );

		// Update the database
		$current_user = dvwaCurrentUser();
		$data = $db->prepare( 'UPDATE users SET password = (:password) WHERE user = (:user);' );
		$data->bindParam( ':password', $pass_new, PDO::PARAM_STR );
		$data->bindParam( ':user', $current_user, PDO::PARAM_STR );
		$data->execute();

		// Feedback for the user
		$html .= "<pre>Password Changed.</pre>";
	}
	else {
		// Issue with passwords matching
		$html .= "<pre>Passwords did not match.</pre>";
	}

	((is_null($___mysqli_res = mysqli_close($GLOBALS["___mysqli_ston"]))) ? false : $___mysqli_res);
}

// Generate Anti-CSRF token
generateSessionToken();

?>
