<?php

$html = "";

if ($_SERVER['REQUEST_METHOD'] == "POST") {
	// Session IDs must be unguessable: use a cryptographically secure random
	// value, never a counter, a timestamp or a hash of either.
	$cookie_value = bin2hex(random_bytes(20));
	$secure = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
	setcookie("dvwaSession", $cookie_value, [
		'expires'  => time() + 3600,
		'path'     => '/vulnerabilities/weak_id/',
		'secure'   => $secure,
		'httponly' => true,
		'samesite' => 'Strict',
	]);
}
?>
