<?php

// Only allow scripts from this server, no third party hosts which anyone
// can upload their own code to.
$headerCSP = "Content-Security-Policy: script-src 'self'; object-src 'none'; base-uri 'self';";

header($headerCSP);

?>
<?php
if (isset ($_POST['include'])) {
	$include = trim ((is_string( $_POST['include'] ) ? $_POST['include'] : ''));

	// Only accept a local script path (no scheme, no host, no protocol
	// relative //host) and encode it for the attribute it goes into.
	if (preg_match ('#^/?(?!/)[A-Za-z0-9._~/-]+(\?[A-Za-z0-9._~=&%-]*)?\z#', $include)) {
		$page[ 'body' ] .= "
	<script src='" . htmlspecialchars ($include, ENT_QUOTES, 'UTF-8') . "'></script>
";
	} else {
		$page[ 'body' ] .= "
	<p>Only scripts hosted on this server can be included.</p>
";
	}
}
$page[ 'body' ] .= '
<form name="csp" method="POST">
	<p>You can include scripts from this server, examine the Content Security Policy and enter a local URL to include here:</p>
	<input size="50" type="text" name="include" value="" id="include" />
	<input type="submit" value="Include" />
</form>
';
