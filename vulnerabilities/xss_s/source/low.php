<?php

if( isset( $_POST[ 'btnSign' ] ) ) {
	// Get input. It is stored as typed and HTML encoded whenever it is
	// displayed (see dvwaGuestbook()), so markup can never reach the page.
	$message = isset( $_POST[ 'mtxMessage' ] ) ? trim( (is_string( $_POST[ 'mtxMessage' ] ) ? $_POST[ 'mtxMessage' ] : '') ) : '';
	$name    = isset( $_POST[ 'txtName' ] ) ? trim( (is_string( $_POST[ 'txtName' ] ) ? $_POST[ 'txtName' ] : '') ) : '';

	// Keep within the size of the database columns
	$message = mb_substr( $message, 0, 300, 'UTF-8' );
	$name    = mb_substr( $name, 0, 100, 'UTF-8' );

	// Update database using a parameterised query
	$data = $db->prepare( 'INSERT INTO guestbook ( comment, name ) VALUES ( :message, :name );' );
	$data->bindParam( ':message', $message, PDO::PARAM_STR );
	$data->bindParam( ':name', $name, PDO::PARAM_STR );
	$data->execute();
}

?>
