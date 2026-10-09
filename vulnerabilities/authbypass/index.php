<?php

define( 'DVWA_WEB_PAGE_TO_ROOT', '../../' );
require_once DVWA_WEB_PAGE_TO_ROOT . 'dvwa/includes/dvwaPage.inc.php';

// Not logged in: off to the login page, like every other DVWA page.
dvwaPageStartup( array( 'authenticated' ) );

/*
Deny by default: the user manager is only for the admin user. Hiding the
menu entry is not access control, so the page checks the user on the
server, first thing and whatever the security level. Any other user gets
the normal DVWA page with an "access denied" message instead of the user
manager: no table, no authbypass.js, no user data. The API behind the page
(get_user_data.php, change_user_details.php) does the same check and
answers 403.
*/
if( dvwaCurrentUser() !== "admin" ) {
	$page = dvwaPageNewGrab();
	$page[ 'title' ]   = 'Access denied' . $page[ 'title_separator' ] . $page[ 'title' ];
	$page[ 'body' ]    = '
<div class="body_padded">
	<h1>Access denied</h1>
	<p>Unauthorised: only the admin user is allowed to use this page.</p>
</div>';
	dvwaHtmlEcho( $page );
	exit;
}

$page = dvwaPageNewGrab();
$page[ 'title' ]   = 'Vulnerability: Authorisation Bypass' . $page[ 'title_separator' ].$page[ 'title' ];
$page[ 'page_id' ] = 'authbypass';
$page[ 'help_button' ]   = 'authbypass';
$page[ 'source_button' ] = 'authbypass';
dvwaDatabaseConnect();

$method            = 'GET';
$vulnerabilityFile = '';
switch( dvwaSecurityLevelGet() ) {
	case 'low':
		$vulnerabilityFile = 'low.php';
		break;
	case 'medium':
		$vulnerabilityFile = 'medium.php';
		break;
	case 'high':
		$vulnerabilityFile = 'high.php';
		break;
	default:
		$vulnerabilityFile = 'impossible.php';
		$method = 'POST';
		break;
}

require_once DVWA_WEB_PAGE_TO_ROOT . "vulnerabilities/authbypass/source/{$vulnerabilityFile}";

$page[ 'body' ] .= '
<div class="body_padded">
	<h1>Vulnerability: Authorisation Bypass</h1>

	<p>This page should only be accessible by the admin user. Your challenge is to gain access to the features using one of the other users, for example <i>gordonb</i> / <i>abc123</i>.</p>

	<div class="vulnerable_code_area">
	<div style="font-weight: bold;color: red;font-size: 120%;" id="save_result"></div>
	<div id="user_form"></div>
	<p>
		Welcome to the user manager, please enjoy updating your user\'s details.
	</p>
	';

$page[ 'body' ] .= "
<script src='authbypass.js'></script>

<table id='user_table'>
	<thead>
		<th>ID</th>
		<th>First Name</th>
		<th>Surname</th>
		<th>Update</th>
	</thead>
	<tbody>
	</tbody>
</table>

<script>
	populate_form();
</script>
";

$page[ 'body' ] .= '
		' . 
		$html
		. '
	</div>
</div>';

dvwaHtmlEcho( $page );

?>
