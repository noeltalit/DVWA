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
	// Answer with a plain DVWA page that only says access was refused: none
	// of the user manager (title, heading, script, table) is sent.
	http_response_code(403);
	$page = dvwaPageNewGrab();
	$page[ 'title' ]   = 'Unauthorised' . $page[ 'title_separator' ] . $page[ 'title' ];
	$page[ 'page_id' ] = '';
	$page[ 'body' ]    = '
<div class="body_padded">
	<h1>Unauthorised</h1>
	<p>Unauthorised (403 Forbidden): you are not allowed to access this page.</p>
</div>';
	dvwaHtmlEcho( $page );
	exit;
}
?>
