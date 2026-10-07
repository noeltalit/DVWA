<?php

if( isset( $_POST[ 'Upload' ] ) ) {
	// Was a file actually uploaded?
	if( !isset( $_FILES[ 'uploaded' ][ 'error' ] ) || $_FILES[ 'uploaded' ][ 'error' ] !== UPLOAD_ERR_OK ||
		!is_uploaded_file( $_FILES[ 'uploaded' ][ 'tmp_name' ] ) ) {
		$html .= '<pre>Your image was not uploaded.</pre>';
	}
	else {
		// File information
		$uploaded_name = (string) $_FILES[ 'uploaded' ][ 'name' ];
		$uploaded_ext  = strtolower( pathinfo( $uploaded_name, PATHINFO_EXTENSION ) );
		$uploaded_size = $_FILES[ 'uploaded' ][ 'size' ];
		$uploaded_tmp  = $_FILES[ 'uploaded' ][ 'tmp_name' ];

		// Work out what the file really is from its content, never from the
		// name or Content-Type the client sent, and make sure the extension
		// agrees with it.
		$allowed_types = array(
			IMAGETYPE_JPEG => array( 'jpg', 'jpeg' ),
			IMAGETYPE_PNG  => array( 'png' ),
		);
		$image_info = @getimagesize( $uploaded_tmp );
		$image_type = ( $image_info !== false ) ? $image_info[ 2 ] : IMAGETYPE_UNKNOWN;

		// Is it an image?
		if( isset( $allowed_types[ $image_type ] ) &&
			in_array( $uploaded_ext, $allowed_types[ $image_type ], true ) &&
			( $uploaded_size < 100000 ) ) {

			// Where are we going to be writing to? Only keep safe characters
			// from the original name (no dots, so no double extensions) and
			// use the extension we validated.
			$target_path = DVWA_WEB_PAGE_TO_ROOT . "hackable/uploads/";
			$target_name = preg_replace( '/[^A-Za-z0-9_-]/', '', pathinfo( $uploaded_name, PATHINFO_FILENAME ) );
			if( $target_name === '' ) {
				$target_name = bin2hex( random_bytes( 8 ) );
			}
			$target_file = substr( $target_name, 0, 64 ) . '.' . $uploaded_ext;

			// Re-encode the image, this strips any metadata and anything
			// hidden in or appended to the original file.
			if( $image_type == IMAGETYPE_JPEG ) {
				$img   = @imagecreatefromjpeg( $uploaded_tmp );
				$saved = ( $img !== false ) && imagejpeg( $img, $target_path . $target_file, 100 );
			}
			else {
				$img   = @imagecreatefrompng( $uploaded_tmp );
				$saved = ( $img !== false ) && imagepng( $img, $target_path . $target_file, 9 );
			}
			unset( $img );

			if( !$saved ) {
				// No
				$html .= '<pre>Your image was not uploaded.</pre>';
			}
			else {
				// Yes!
				$html .= "<pre>{$target_path}{$target_file} succesfully uploaded!</pre>";
			}
		}
		else {
			// Invalid file
			$html .= '<pre>Your image was not uploaded. We can only accept JPEG or PNG images.</pre>';
		}
	}
}

?>
