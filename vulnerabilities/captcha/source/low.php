<?php

if( isset( $_POST[ 'Change' ] ) && isset( $_POST[ 'step' ] ) && ( $_POST[ 'step' ] == '1' ) ) {
	// Hide the CAPTCHA form
	$hide_form = true;

	// Get input
	$pass_new  = isset( $_POST[ 'password_new' ] ) ? (is_string( $_POST[ 'password_new' ] ) ? $_POST[ 'password_new' ] : '') : '';
	$pass_conf = isset( $_POST[ 'password_conf' ] ) ? (is_string( $_POST[ 'password_conf' ] ) ? $_POST[ 'password_conf' ] : '') : '';

	// Forget any CAPTCHA that was passed before
	unset( $_SESSION[ 'captcha_passed' ], $_SESSION[ 'captcha_password' ] );

	// Check CAPTCHA from 3rd party
	$resp = recaptcha_check_answer(
		$_DVWA[ 'recaptcha_private_key' ],
		isset( $_POST[ 'g-recaptcha-response' ] ) ? (is_string( $_POST[ 'g-recaptcha-response' ] ) ? $_POST[ 'g-recaptcha-response' ] : '') : ''
	);

	// Did the CAPTCHA fail?
	if( !$resp ) {
		// What happens when the CAPTCHA was entered incorrectly
		$html     .= "<pre><br />The CAPTCHA was incorrect. Please try again.</pre>";
		$hide_form = false;
		return;
	}
	else {
		// CAPTCHA was correct. Do both new passwords match?
		if( $pass_new === $pass_conf ) {
			// Remember on the server that the CAPTCHA was passed and which
			// password was asked for. Step 2 only trusts this, never anything
			// sent in the request.
			$_SESSION[ 'captcha_passed' ]   = true;
			$_SESSION[ 'captcha_password' ] = md5( mysqli_real_escape_string( $GLOBALS["___mysqli_ston"], $pass_new ) );

			// Show next stage for the user
			$html .= "
				<pre><br />You passed the CAPTCHA! Click the button to confirm your changes.<br /></pre>
				<form action=\"#\" method=\"POST\">
					<input type=\"hidden\" name=\"step\" value=\"2\" />
					<input type=\"submit\" name=\"Change\" value=\"Change\" />
				</form>";
		}
		else {
			// Both new passwords do not match.
			$html     .= "<pre>Both passwords must match.</pre>";
			$hide_form = false;
		}
	}
}

if( isset( $_POST[ 'Change' ] ) && isset( $_POST[ 'step' ] ) && ( $_POST[ 'step' ] == '2' ) ) {
	// Hide the CAPTCHA form
	$hide_form = true;

	// Check to see if they really did stage 1
	if( empty( $_SESSION[ 'captcha_passed' ] ) || !isset( $_SESSION[ 'captcha_password' ] ) ) {
		$html     .= "<pre><br />You have not passed the CAPTCHA.</pre>";
		$hide_form = false;
		return;
	}

	// A passed CAPTCHA can only be used once
	$pass_new = $_SESSION[ 'captcha_password' ];
	unset( $_SESSION[ 'captcha_passed' ], $_SESSION[ 'captcha_password' ] );

	// Update database
	$current_user = dvwaCurrentUser();
	$data = $db->prepare( 'UPDATE users SET password = (:password) WHERE user = (:user);' );
	$data->bindParam( ':password', $pass_new, PDO::PARAM_STR );
	$data->bindParam( ':user', $current_user, PDO::PARAM_STR );
	$data->execute();

	// Feedback for the end user
	$html .= "<pre>Password Changed.</pre>";

	((is_null($___mysqli_res = mysqli_close($GLOBALS["___mysqli_ston"]))) ? false : $___mysqli_res);
}

?>
