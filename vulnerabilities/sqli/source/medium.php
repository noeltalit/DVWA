<?php

if( isset( $_POST[ 'Submit' ] ) ) {
	// Get input
	$id = isset( $_POST[ 'id' ] ) ? trim( (is_string( $_POST[ 'id' ] ) ? $_POST[ 'id' ] : '') ) : '';

	// Only accept a plain, positive user ID
	if( ctype_digit( $id ) ) {
		$id = intval( $id );

		switch ($_DVWA['SQLI_DB']) {
			case MYSQL:
				// Check database using a parameterised query
				$data = $db->prepare( 'SELECT first_name, last_name FROM users WHERE user_id = (:id);' );
				$data->bindParam( ':id', $id, PDO::PARAM_INT );
				$data->execute();

				// Get results
				while( $row = $data->fetch() ) {
					// Display values
					$first = htmlspecialchars( $row["first_name"], ENT_QUOTES, 'UTF-8' );
					$last  = htmlspecialchars( $row["last_name"], ENT_QUOTES, 'UTF-8' );

					// Feedback for end user
					$html .= "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>";
				}
				break;
			case SQLITE:
				global $sqlite_db_connection;

				$stmt = $sqlite_db_connection->prepare( 'SELECT first_name, last_name FROM users WHERE user_id = :id;' );
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

// This is used later on in the index.php page
// Setting it here so we can close the database connection in here like in the rest of the source scripts
$query  = "SELECT COUNT(*) FROM users;";
$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>Something went wrong.</pre>' );
$number_of_rows = mysqli_fetch_row( $result )[0];

mysqli_close($GLOBALS["___mysqli_ston"]);
?>
