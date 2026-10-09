<?php
define( 'DVWA_WEB_PAGE_TO_ROOT', '../../' );
require_once DVWA_WEB_PAGE_TO_ROOT . 'dvwa/includes/dvwaPage.inc.php';

dvwaDatabaseConnect();

/*
Only the admin is allowed to retrieve the data, whatever the security level.
Other users get the same JSON error the page script already understands
(result "fail"), as a normal API answer, and no user record at all.
*/
if (dvwaCurrentUser() != "admin") {
	header ("Content-Type: application/json");
	print json_encode (array ("result" => "fail", "error" => "Access denied"));
	exit;
}

$query  = "SELECT user_id, first_name, last_name FROM users";
$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query );

$users = array();

while ($row = mysqli_fetch_row($result) ) { 
	// The names are written into the page as HTML by authbypass.js
	$user_id = $row[0];
	$first_name = htmlspecialchars( (string) $row[1], ENT_QUOTES, 'UTF-8' );
	$surname = htmlspecialchars( (string) $row[2], ENT_QUOTES, 'UTF-8' );

	$user = array (
					"user_id" => $user_id,
					"first_name" => $first_name,
					"surname" => $surname
				);
	$users[] = $user;
}

header ("Content-Type: application/json");
print json_encode ($users);
exit;
?>
