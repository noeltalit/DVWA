<?php

$change = false;
$request_type = "html";
$return_message = "Request Failed";

if ($_SERVER['REQUEST_METHOD'] == "POST" && array_key_exists ("CONTENT_TYPE", $_SERVER) && $_SERVER['CONTENT_TYPE'] == "application/json") {
	$data = json_decode(file_get_contents('php://input'), true);
	$request_type = "json";
	if (is_array($data) &&
		array_key_exists("HTTP_USER_TOKEN", $_SERVER) &&
		array_key_exists("password_current", $data) &&
		array_key_exists("password_new", $data) &&
		array_key_exists("password_conf", $data) &&
		array_key_exists("Change", $data)) {
		$token = $_SERVER['HTTP_USER_TOKEN'];
		$pass_curr = $data["password_current"];
		$pass_new = $data["password_new"];
		$pass_conf = $data["password_conf"];
		$change = true;
	}
} else {
	if (array_key_exists("user_token", $_REQUEST) &&
		array_key_exists("password_current", $_REQUEST) &&
		array_key_exists("password_new", $_REQUEST) &&
		array_key_exists("password_conf", $_REQUEST) &&
		array_key_exists("Change", $_REQUEST)) {
		$token = $_REQUEST["user_token"];
		$pass_curr = $_REQUEST["password_current"];
		$pass_new = $_REQUEST["password_new"];
		$pass_conf = $_REQUEST["password_conf"];
		$change = true;
	}
}

if ($change) {
	// Check Anti-CSRF token
	checkToken( $token, isset( $_SESSION[ 'session_token' ] ) ? $_SESSION[ 'session_token' ] : null, 'index.php' );

	// The token alone can be stolen (e.g. read from the page by injected
	// script), so the change also needs the current password, which a
	// forged request can't know.
	$pass_curr = is_string( $pass_curr ) ? $pass_curr : '';
	$pass_new  = is_string( $pass_new ) ? $pass_new : '';
	$pass_conf = is_string( $pass_conf ) ? $pass_conf : '';

	$pass_curr = mysqli_real_escape_string ($GLOBALS["___mysqli_ston"], $pass_curr);
	$pass_curr = md5( $pass_curr );

	$current_user = dvwaCurrentUser();
	$data = $db->prepare( 'SELECT password FROM users WHERE user = (:user) AND password = (:password) LIMIT 1;' );
	$data->bindParam( ':user', $current_user, PDO::PARAM_STR );
	$data->bindParam( ':password', $pass_curr, PDO::PARAM_STR );
	$data->execute();

	// Do the passwords match and is the current password right?
	if( ( $pass_new === $pass_conf ) && ( $data->rowCount() == 1 ) ) {
		// They do!
		$pass_new = mysqli_real_escape_string ($GLOBALS["___mysqli_ston"], $pass_new);
		$pass_new = md5( $pass_new );

		// Update the database
		$data = $db->prepare( 'UPDATE users SET password = (:password) WHERE user = (:user);' );
		$data->bindParam( ':password', $pass_new, PDO::PARAM_STR );
		$data->bindParam( ':user', $current_user, PDO::PARAM_STR );
		$data->execute();

		// Feedback for the user
		$return_message = "Password Changed.";
	}
	else {
		// Issue with passwords matching
		$return_message = "Passwords did not match or current password incorrect.";
	}

	mysqli_close($GLOBALS["___mysqli_ston"]);

	if ($request_type == "json") {
		generateSessionToken();
		header ("Content-Type: application/json");
		print json_encode (array("Message" =>$return_message));
		exit;
	} else {
		$html .= "<pre>" . $return_message . "</pre>";
	}
}

// Generate Anti-CSRF token
generateSessionToken();

?>
