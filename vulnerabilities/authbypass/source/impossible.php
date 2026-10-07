<?php
/*

Only the admin user is allowed to access this page

*/

if (dvwaCurrentUser() != "admin") {
	http_response_code(403);
	print "Unauthorised";
	exit;
}
?>
