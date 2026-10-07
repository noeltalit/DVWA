<?php

if (array_key_exists ("redirect", $_GET) && $_GET['redirect'] != "") {
	// Only ever redirect to one of our own quote pages. Anything else
	// (absolute URLs, protocol relative //host, other paths...) is refused.
	if (is_string ($_GET['redirect']) && preg_match ('/^info\.php\?id=[0-9]+\z/', $_GET['redirect'])) {
		header ("location: " . $_GET['redirect']);
		exit;
	} else {
		?>
		<p>You can only redirect to the info page.</p>
		<?php
		exit;
	}
}

?>
<p>Missing redirect target.</p>
<?php
exit;
?>
