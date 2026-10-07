<?php

// Messages are protected with authenticated encryption (AES-256-GCM) and a
// random key that only exists on the server. XOR with a fixed, repeating key
// gives the key away to anyone who can encode a message they already know.
function encrypt_message ($cleartext, $key) {
	$iv = random_bytes (12);
	$tag = "";
	$ciphertext = openssl_encrypt ($cleartext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
	return base64_encode ($iv . $tag . $ciphertext);
}

function decrypt_message ($message, $key) {
	$raw = base64_decode ($message, true);
	if ($raw === false || strlen ($raw) < 28) {
		throw new Exception ("The message could not be decoded");
	}
	$cleartext = openssl_decrypt (substr ($raw, 28), 'aes-256-gcm', $key, OPENSSL_RAW_DATA, substr ($raw, 0, 12), substr ($raw, 12, 16));
	if ($cleartext === false) {
		throw new Exception ("The message could not be decoded");
	}
	return $cleartext;
}

// Your own key, used by the encode/decode form
if (!isset ($_SESSION['crypto_low_key'])) {
	$_SESSION['crypto_low_key'] = random_bytes (32);
}
$key = $_SESSION['crypto_low_key'];

// The intercepted message was exchanged by other people, under a key you
// don't have, and the password it carries isn't hard coded anywhere.
if (!isset ($_SESSION['crypto_low_intercepted'])) {
	$_SESSION['crypto_low_password'] = bin2hex (random_bytes (8));
	$_SESSION['crypto_low_intercepted'] = encrypt_message ("Your new password is: " . $_SESSION['crypto_low_password'], random_bytes (32));
}

$errors = "";
$success = "";
$messages = "";
$encoded = null;
$encode_radio_selected = " checked='checked' ";
$decode_radio_selected = " ";
$message = "";

if ($_SERVER['REQUEST_METHOD'] == "POST") {
	try {
		if (array_key_exists ('message', $_POST)) {
			$message = (is_string( $_POST['message'] ) ? $_POST['message'] : '');
			if (array_key_exists ('direction', $_POST) && $_POST['direction'] == "decode") {
				$encode_radio_selected = " ";
				$decode_radio_selected = " checked='checked' ";
				$encoded = decrypt_message ($message, $key);
			} else {
				$encoded = encrypt_message ($message, $key);
			}
		}
		if (array_key_exists ('password', $_POST)) {
			$password = (is_string( $_POST['password'] ) ? $_POST['password'] : '');
			if (hash_equals ($_SESSION['crypto_low_password'], $password)) {
				$success = "Welcome back user";
			} else {
				$errors = "Login Failed";
			}
		}
	} catch(Exception $e) {
		$errors = $e->getMessage();
	}
}

$html = "
		<p>
		This system will allow you to exchange messages with your friends without anyone else being able to read them. Use the box below to encode and decode messages.
		</p>
		<form name=\"xor\" method='post' action=\"" . htmlspecialchars ($_SERVER['PHP_SELF'], ENT_QUOTES, 'UTF-8') . "\">
			<p>
				<label for='message'>Message:</lable><br />
				<textarea style='width: 600px; height: 56px' id='message' name='message'>" . htmlentities ($message) . "</textarea>
			</p>
			<p>
				<input type='radio' value='encode' name='direction' id='direction_encode' " . $encode_radio_selected . "><label for='direction_encode'>Encode</label> or 
				<input type='radio' value='decode' name='direction' id='direction_decode' " . $decode_radio_selected . "><label for='direction_decode'>Decode</label>
			</p>
			<p>
				<input type=\"submit\" value=\"Submit\">
			</p>
		</form>
";

if (!is_null ($encoded)) {
	$html .= "
			<p>
				<label for='encoded'>Message:</lable><br />
				<textarea readonly='readonly' style='width: 600px; height: 56px' id='encoded' name='encoded'>" . htmlentities ($encoded) . "</textarea>
			</p>";
}

$html .= "
		<hr>
		<p>
		You have intercepted the following message, decode it and log in below.
		</p>
		<p>
		<textarea readonly='readonly' style='width: 600px; height: 56px' id='encoded' name='encoded'>" . htmlentities ($_SESSION['crypto_low_intercepted']) . "</textarea>
		</p>
";

if ($errors != "") {
	$html .= '<div class="warning">' . $errors . '</div>';
}

if ($messages != "") {
	$html .= '<div class="nearly">' . $messages . '</div>';
}

if ($success != "") {
	$html .= '<div class="success">' . $success . '</div>';
}

$html .= "
		<form name=\"ecb\" method='post' action=\"" . htmlspecialchars ($_SERVER['PHP_SELF'], ENT_QUOTES, 'UTF-8') . "\">
			<p>
				<label for='password'>Password:</lable><br />
<input type='password' id='password' name='password'>
			</p>
			<p>
				<input type=\"submit\" value=\"Login\">
			</p>
		</form>
";
?>
