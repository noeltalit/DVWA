<?php

if( isset( $_POST[ 'Submit' ]  ) ) {
	// Get input
	$target = isset( $_REQUEST[ 'ip' ] ) ? trim( (is_string( $_REQUEST[ 'ip' ] ) ? $_REQUEST[ 'ip' ] : '') ) : '';

	// Only accept an IP address or a hostname. Anything else (shell
	// metacharacters, spaces, leading dashes for ping options...) is rejected.
	$is_ip   = ( filter_var( $target, FILTER_VALIDATE_IP ) !== false );
	$is_host = ( preg_match( '/^(?=.{1,253}\z)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\z/', $target ) === 1 );

	if( $is_ip || $is_host ) {
		// Never let the shell interpret the value
		$target = escapeshellarg( $target );

		// Determine OS and execute the ping command.
		if( stristr( php_uname( 's' ), 'Windows NT' ) ) {
			// Windows
			$cmd = shell_exec( 'ping  ' . $target );
		}
		else {
			// *nix
			$cmd = shell_exec( 'ping  -c 4 ' . $target );
		}

		// Feedback for the end user
		$html .= "<pre>" . htmlspecialchars( (string) $cmd, ENT_QUOTES, 'UTF-8' ) . "</pre>";
	}
	else {
		// Ops. Let the user know there's a mistake
		$html .= '<pre>ERROR: You have entered an invalid IP or hostname.</pre>';
	}
}

?>
