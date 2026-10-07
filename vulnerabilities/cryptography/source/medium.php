<?php
// Tokens are protected with authenticated encryption (AES-256-GCM, random IV)
// so any change to them, such as swapping ECB blocks between tokens, is
// detected. The key is random and only exists on the server.
function encrypt ($plaintext, $key) {
	$iv = random_bytes (12);
	$tag = "";
	$e = openssl_encrypt ($plaintext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
	return $iv . $tag . $e;
}

function decrypt ($ciphertext, $key) {
	if (strlen ($ciphertext) < 28) {
		throw new Exception ("Decryption failed");
	}
	$e = openssl_decrypt (substr ($ciphertext, 28), 'aes-256-gcm', $key, OPENSSL_RAW_DATA, substr ($ciphertext, 0, 12), substr ($ciphertext, 12, 16));
	if ($e === false) {
		throw new Exception ("Decryption failed");
	}
	return $e;
}

if (!isset ($_SESSION['crypto_medium_key'])) {
	$_SESSION['crypto_medium_key'] = random_bytes (32);
}
$key = $_SESSION['crypto_medium_key'];

// The three captured session tokens
$sooty_token = bin2hex (encrypt (json_encode (array ("user" => "sooty", "ex" => time() - 86400, "level" => "admin", "bio" => "Izzy wizzy let's get busy")), $key));
$sweep_token = bin2hex (encrypt (json_encode (array ("user" => "sweep", "ex" => time() - 86400, "level" => "user", "bio" => "Squeak squeak")), $key));
$soo_token   = bin2hex (encrypt (json_encode (array ("user" => "soo", "ex" => time() + 3600, "level" => "user", "bio" => "Panda")), $key));

$errors = "";
$success = "";
$messages = "";

if ($_SERVER['REQUEST_METHOD'] == "POST") {
	try {
		if (!array_key_exists ('token', $_POST)) {
			throw new Exception ("No token passed");
		} else {
			$token = trim ((is_string( $_POST['token'] ) ? $_POST['token'] : ''));
			if ($token === "" || strlen ($token) % 2 != 0 || !ctype_xdigit ($token)) {
				throw new Exception ("Token is in wrong format");
			} else {
				$decrypted = decrypt(hex2bin ($token), $key);

				$user = json_decode ($decrypted);
				if (!is_object ($user) || !isset ($user->user, $user->ex, $user->level)) {
					throw new Exception ("Could not decode JSON object.");
				}

				if ($user->user == "sweep" && $user->ex > time() && $user->level == "admin") {
					$success = "Welcome administrator Sweep";
				} else {
					$messages = "Login successful but not as the right user.";
				}
			}
		}
	} catch(Exception $e) {
		$errors = $e->getMessage();
	}
}

$html = "
		<p>
		You have managed to get hold of three session tokens for an application you think is using poor cryptography to protect its secrets:
		</p>
		<p>
		<strong>Sooty (admin), session expired</strong>
		</p>
		<p>
<textarea style='width: 600px; height: 56px'>" . $sooty_token . "</textarea>
		</p>
		<p>
		<strong>Sweep (user), session expired</strong>
		</p>
		<p>
<textarea style='width: 600px; height: 56px'>" . $sweep_token . "</textarea>
		</p>
		<p>
		<strong>Soo (user), session valid</strong>
		</p>
		<p>
<textarea style='width: 600px; height: 56px'>" . $soo_token . "</textarea>
		</p>
		<p>
		Based on the documentation, you know the format of the token is:
		</p>
		<pre><code>{
    \"user\": \"example\",
    \"ex\": 1723620372,
    \"level\": \"user\",
    \"bio\": \"blah\"
}</code></pre>
<p>
You also spot this comment in the docs:
</p>
<blockquote><i>
To ensure your security, we use aes-256-gcm throughout our application.
</i></blockquote>

		<hr>
		<p>
		Manipulate the session tokens you have captured to log in as Sweep with admin privileges.
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
				<label for='token'>Token:</lable><br />
<textarea style='width: 600px; height: 56px' id='token' name='token'></textarea>
			</p>
			<p>
				<input type=\"submit\" value=\"Submit\">
			</p>
		</form>
";
?>
