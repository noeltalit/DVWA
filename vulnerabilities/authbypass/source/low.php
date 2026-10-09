<?php
/*

Only the admin user is allowed to access this page.

Hiding the menu entry (see dvwaHtmlEcho) is not access control: the URL can
simply be requested. The page checks the user itself, and so do the
endpoints behind it (get_user_data.php and change_user_details.php).

*/

if (dvwaCurrentUser() != "admin") {
	http_response_code(403);
	print "Unauthorised";
	exit;
}
?>
