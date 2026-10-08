<?php
/*

Only the admin user is allowed to access this page.

Hiding the menu entry isn't access control: anyone who knows the URL could
load the user manager. So the page itself checks the user and anyone else
gets a real 403 Forbidden, rendered as a normal DVWA page. The API behind
the page (get_user_data.php and change_user_details.php) does the same
admin check and answers 403 too.

*/

if (dvwaCurrentUser() != "admin") {
	http_response_code(403);
	$page[ 'body' ] .= '
<div class="body_padded">
	<h1>Vulnerability: Authorisation Bypass</h1>

	<div class="vulnerable_code_area">
		<p><strong>Unauthorised</strong> (403 Forbidden): only the admin user is allowed to access the user manager.</p>
	</div>
</div>';
	dvwaHtmlEcho( $page );
	exit;
}
?>
