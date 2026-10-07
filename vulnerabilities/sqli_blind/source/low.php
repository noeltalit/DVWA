<?php

if( isset( $_GET[ 'Submit' ] ) ) {
	// Get input
	$id = isset( $_GET[ 'id' ] ) ? trim( (is_string( $_GET[ 'id' ] ) ? $_GET[ 'id' ] : '') ) : '';
	$exists = false;

	// Only accept a plain, positive user ID
	if( ctype_digit( $id ) ) {
		$id = intval( $id );

		switch ($_DVWA['SQLI_DB']) {
			case MYSQL:
				// Check database using a parameterised query
				try {
					$data = $db->prepare( 'SELECT first_name, last_name FROM users WHERE user_id = (:id);' );
					$data->bindParam( ':id', $id, PDO::PARAM_INT );
					$data->execute();
					$exists = ( $data->fetch() !== false );
				} catch (Exception $e) {
					$exists = false;
				}

				((is_null($___mysqli_res = mysqli_close($GLOBALS["___mysqli_ston"]))) ? false : $___mysqli_res);
				break;
			case SQLITE:
				global $sqlite_db_connection;

				try {
					$stmt = $sqlite_db_connection->prepare( 'SELECT first_name, last_name FROM users WHERE user_id = :id;' );
					$stmt->bindValue( ':id', $id, SQLITE3_INTEGER );
					$results = $stmt->execute();
					$row = $results->fetchArray();
					$exists = $row !== false;
				} catch(Exception $e) {
					$exists = false;
				}

				break;
		}
	}

	if ($exists) {
		// Feedback for end user
		$html .= '<pre>User ID exists in the database.</pre>';
	} else {
		// Feedback for end user
		$html .= '<pre>User ID is MISSING from the database.</pre>';
	}

}

?>
