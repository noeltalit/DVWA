<?php

// The page we wish to display
$file = isset( $_GET[ 'page' ] ) ? $_GET[ 'page' ] : null;

// Only allow include.php or file{1..3}.php. Anything else (local paths,
// directory traversal, remote URLs, stream wrappers...) is refused.
$allowedFileNames = [
	'include.php',
	'file1.php',
	'file2.php',
	'file3.php',
];

if( $file !== null && !in_array( $file, $allowedFileNames, true ) ) {
	// This isn't the page we want!
	echo "ERROR: File not found!";
	exit;
}

?>
