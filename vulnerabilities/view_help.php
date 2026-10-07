<?php

define( 'DVWA_WEB_PAGE_TO_ROOT', '../' );
require_once DVWA_WEB_PAGE_TO_ROOT . 'dvwa/includes/dvwaPage.inc.php';

dvwaPageStartup( array( 'authenticated' ) );

$page = dvwaPageNewGrab();
$page[ 'title' ] = 'Help' . $page[ 'title_separator' ].$page[ 'title' ];

// The help file is executed, so the path must only ever point at one of the
// real help files: a known module name and a plain locale code.
$help_file = null;
if (array_key_exists ("id", $_GET) &&
	array_key_exists ("security", $_GET) &&
	array_key_exists ("locale", $_GET) &&
	is_string ($_GET[ 'id' ]) && preg_match ('/^[a-z_]+\z/', $_GET[ 'id' ]) &&
	is_string ($_GET[ 'locale' ]) && preg_match ('/^[a-z]{2}\z/', $_GET[ 'locale' ])) {
	$id       = $_GET[ 'id' ];
	$security = $_GET[ 'security' ];
	$locale = $_GET[ 'locale' ];

	if ($locale == 'en') {
		$help_file = DVWA_WEB_PAGE_TO_ROOT . "vulnerabilities/{$id}/help/help.php";
	} else {
		$help_file = DVWA_WEB_PAGE_TO_ROOT . "vulnerabilities/{$id}/help/help.{$locale}.php";
	}
	if (!is_file ($help_file)) {
		$help_file = null;
	}
}

if ($help_file !== null) {
	ob_start();
	eval( '?>' . file_get_contents( $help_file ) . '<?php ' );
	$help = ob_get_contents();
	ob_end_clean();
} else {
	$help = "<p>Not Found</p>";
}

$page[ 'body' ] .= "
<script src='/vulnerabilities/help.js'></script>
<link rel='stylesheet' type='text/css' href='/vulnerabilities/help.css' />

<div class=\"body_padded\">
	{$help}
</div>\n";

dvwaHelpHtmlEcho( $page );

?>
