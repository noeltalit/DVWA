<?php

// Is there any input?
if( array_key_exists( "name", $_GET ) && $_GET[ 'name' ] != NULL ) {
	// Get input, encoded for the HTML context it is written into
	$name = htmlspecialchars( (is_string( $_GET[ 'name' ] ) ? $_GET[ 'name' ] : ''), ENT_QUOTES, 'UTF-8' );

	// Feedback for end user
	$html .= "<pre>Hello {$name}</pre>";
}

?>
