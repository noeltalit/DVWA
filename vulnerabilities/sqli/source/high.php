<?php

if( isset( $_SESSION [ 'id' ] ) ) {
	// Get input
	$id = trim( (is_string( $_SESSION[ 'id' ] ) ? $_SESSION[ 'id' ] : '') );

	// Only accept a plain, positive user ID
	if( ctype_digit( $id ) ) {
		$id = intval( $id );

		switch ($_DVWA['SQLI_DB']) {
			case MYSQL:
				// Check database using a parameterised query
				$data = $db->prepare( 'SELECT first_name, last_name FROM users WHERE user_id = (:id) LIMIT 1;' );
				$data->bindParam( ':id', $id, PDO::PARAM_INT );
				$data->execute();

				// Get results
				while( $row = $data->fetch() ) {
					// Get values
					$first = htmlspecialchars( $row["first_name"], ENT_QUOTES, 'UTF-8' );
					$last  = htmlspecialchars( $row["last_name"], ENT_QUOTES, 'UTF-8' );

					// Feedback for end user
					$html .= "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>";
				}

				((is_null($___mysqli_res = mysqli_close($GLOBALS["___mysqli_ston"]))) ? false : $___mysqli_res);
				break;
			case SQLITE:
				global $sqlite_db_connection;

				$stmt = $sqlite_db_connection->prepare( 'SELECT first_name, last_name FROM users WHERE user_id = :id LIMIT 1;' );
				$stmt->bindValue( ':id', $id, SQLITE3_INTEGER );
				$results = $stmt->execute();

				if ($results) {
					while ($row = $results->fetchArray()) {
						// Get values
						$first = htmlspecialchars( $row["first_name"], ENT_QUOTES, 'UTF-8' );
						$last  = htmlspecialchars( $row["last_name"], ENT_QUOTES, 'UTF-8' );

						// Feedback for end user
						$html .= "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>";
					}
				}
				break;
		}
	}
	else {
		$html .= '<pre>ERROR: The user ID must be a number.</pre>';
	}
}

?>
