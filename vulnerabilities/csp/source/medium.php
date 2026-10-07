<?php

// No 'unsafe-inline' and no reusable nonce, only scripts from this server run.
$headerCSP = "Content-Security-Policy: script-src 'self'; object-src 'none'; base-uri 'self';";

header($headerCSP);

?>
<?php
if (isset ($_POST['include'])) {
// Whatever is entered is shown as text, never as markup
$page[ 'body' ] .= "
	" . htmlspecialchars ((is_string( $_POST['include'] ) ? $_POST['include'] : ''), ENT_QUOTES, 'UTF-8') . "
";
}
$page[ 'body' ] .= '
<form name="csp" method="POST">
	<p>Whatever you enter here gets displayed in the page, see if you can get an alert box to pop up.</p>
	<input size="50" type="text" name="include" value="" id="include" />
	<input type="submit" value="Include" />
</form>
';
