<?php

if( isset( $_POST[ 'Change' ] ) ) {
	// Check Anti-CSRF token
	checkToken( isset( $_REQUEST[ 'user_token' ] ) ? $_REQUEST[ 'user_token' ] : null, isset( $_SESSION[ 'session_token' ] ) ? $_SESSION[ 'session_token' ] : null, 'index.php' );

	// Hide the CAPTCHA form
	$hide_form = true;

	// Get input
	$pass_new  = isset( $_POST[ 'password_new' ] ) ? (is_string( $_POST[ 'password_new' ] ) ? $_POST[ 'password_new' ] : '') : '';
	$pass_conf = isset( $_POST[ 'password_conf' ] ) ? (is_string( $_POST[ 'password_conf' ] ) ? $_POST[ 'password_conf' ] : '') : '';

	// Check CAPTCHA from 3rd party. Only the real answer counts, there is no
	// other way round it.
	$resp = recaptcha_check_answer(
		$_DVWA[ 'recaptcha_private_key' ],
		isset( $_POST[ 'g-recaptcha-response' ] ) ? (is_string( $_POST[ 'g-recaptcha-response' ] ) ? $_POST[ 'g-recaptcha-response' ] : '') : ''
	);

	if( $resp ) {
		// CAPTCHA was correct. Do both new passwords match?
		if ($pass_new === $pass_conf) {
			$pass_new = mysqli_real_escape_string( $GLOBALS["___mysqli_ston"], $pass_new );
			$pass_new = md5( $pass_new );

			// Update database
			$current_user = dvwaCurrentUser();
			$data = $db->prepare( 'UPDATE users SET password = (:password) WHERE user = (:user) LIMIT 1;' );
			$data->bindParam( ':password', $pass_new, PDO::PARAM_STR );
			$data->bindParam( ':user', $current_user, PDO::PARAM_STR );
			$data->execute();

			// Feedback for user
			$html .= "<pre>Password Changed.</pre>";

		} else {
			// Ops. Password mismatch
			$html     .= "<pre>Both passwords must match.</pre>";
			$hide_form = false;
		}

	} else {
		// What happens when the CAPTCHA was entered incorrectly
		$html     .= "<pre><br />The CAPTCHA was incorrect. Please try again.</pre>";
		$hide_form = false;
		return;
	}

	((is_null($___mysqli_res = mysqli_close($GLOBALS["___mysqli_ston"]))) ? false : $___mysqli_res);
}

// Generate Anti-CSRF token
generateSessionToken();

?>
