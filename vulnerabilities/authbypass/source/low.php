<?php
/*

Only the admin user is allowed to access this page.

Hiding the menu entry isn't access control: anyone who knows the URL could
load the user manager. So the page itself checks the user on the server and
anyone else gets the normal DVWA page saying access is denied, without the
user manager. The API behind the page (get_user_data.php and
change_user_details.php) does the same admin check.

*/

if (dvwaCurrentUser() != "admin") {
	$page = dvwaPageNewGrab();
	$page[ 'title' ] = 'Access denied' . $page[ 'title_separator' ] . $page[ 'title' ];
	$page[ 'body' ]  = '
<div class="body_padded">
	<h1>Access denied</h1>
	<p>Unauthorised: only the admin user is allowed to use this page.</p>
</div>';
	dvwaHtmlEcho( $page );
	exit;
}
?>
