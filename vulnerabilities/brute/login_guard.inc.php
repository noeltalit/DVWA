<?php
/*
 * Login guard for the Brute Force pages.
 *
 * Every login attempt goes through bruteLoginAttempt(), which keeps a
 * failed-attempt counter per (security level, account) on disk, the same
 * policy as the impossible level (users.failed_login / last_login):
 *
 *  - after BRUTE_GUARD_MAX_FAILURES failed logins in a row the account is
 *    locked for BRUTE_GUARD_LOCKOUT seconds, and every attempt made while it
 *    is locked restarts that time;
 *  - while it is locked the password is NOT checked at all, so a guessing
 *    run can't find the right password even if it is in the list;
 *  - a wrong password and a locked account get exactly the same answer
 *    ("Username and/or password incorrect." in the normal page, 200, no
 *    sleep()), so the responses don't tell a guessing tool anything;
 *  - a successful login resets the counter, so a user who mistypes once or
 *    twice can still log in.
 *
 * The state file is held under an exclusive lock for the whole
 * check-password-and-record step, so parallel guesses (e.g. hydra's 16
 * tasks) are serialised and can't race past the counter. The account is
 * looked up first and the counter is keyed on the stored user name, so
 * "Admin" or "admin " (which MySQL matches as "admin") share the counter of
 * "admin". The counter is kept per security level so that guessing on one
 * level doesn't lock the account on the others.
 */

define( 'BRUTE_GUARD_MAX_FAILURES', 3 );
define( 'BRUTE_GUARD_LOCKOUT', 15 * 60 );    // seconds

function bruteGuardDir() {
	$candidates = array( rtrim( sys_get_temp_dir(), '/\\' ) . DIRECTORY_SEPARATOR . 'dvwa_brute_guard',
	                     __DIR__ . DIRECTORY_SEPARATOR . '.guard' );
	foreach( $candidates as $dir ) {
		if( is_dir( $dir ) || @mkdir( $dir, 0700, true ) ) {
			if( is_writable( $dir ) ) {
				return $dir;
			}
		}
	}
	return null;
}

/*
 * Returns array( 'status' => 'ok' | 'failed' | 'locked', 'row' => user row or null )
 */
function bruteLoginAttempt( $db, $level, $user, $pass ) {
	$result = array( 'status' => 'failed', 'row' => null );

	if( !is_string( $user ) || !is_string( $pass ) || $user === '' || strlen( $user ) > 64 || strlen( $pass ) > 1024 ) {
		return $result;
	}

	// Look the account up with a prepared statement
	$stmt = $db->prepare( 'SELECT user, password, avatar FROM users WHERE user = (:user) LIMIT 1;' );
	$stmt->bindValue( ':user', $user, PDO::PARAM_STR );
	$stmt->execute();
	$row = $stmt->fetch( PDO::FETCH_ASSOC );

	$account = ( $row !== false ) ? strtolower( (string) $row[ 'user' ] ) : strtolower( rtrim( $user ) );
	$key     = hash( 'sha256', $level . "\0" . $account );

	$dir = bruteGuardDir();
	$fp  = ( $dir !== null ) ? @fopen( $dir . DIRECTORY_SEPARATOR . $key, 'c+' ) : false;
	if( $fp === false || !flock( $fp, LOCK_EX ) ) {
		// Can't track attempts: refuse rather than allow unlimited guessing
		if( $fp !== false ) {
			fclose( $fp );
		}
		$result[ 'status' ] = 'locked';
		return $result;
	}

	$state = json_decode( stream_get_contents( $fp ), true );
	if( !is_array( $state ) ) {
		$state = array();
	}
	$failures   = isset( $state[ 'failures' ] ) ? intval( $state[ 'failures' ] ) : 0;
	$lock_until = isset( $state[ 'lock_until' ] ) ? intval( $state[ 'lock_until' ] ) : 0;
	$now        = time();

	if( $failures >= BRUTE_GUARD_MAX_FAILURES && $lock_until > $now ) {
		// Locked: don't even look at the password, and restart the lockout
		$failures++;
		$lock_until = $now + BRUTE_GUARD_LOCKOUT;
		$result[ 'status' ] = 'locked';
	}
	else {
		if( $lock_until <= $now && $failures >= BRUTE_GUARD_MAX_FAILURES ) {
			// The lockout is over, start counting again
			$failures = 0;
		}

		$valid = false;
		if( $row !== false ) {
			$valid = hash_equals( strtolower( (string) $row[ 'password' ] ), md5( $pass ) );
		}
		else {
			// Same work for unknown accounts
			hash_equals( md5( '' ), md5( $pass ) );
		}

		if( $valid ) {
			$failures   = 0;
			$lock_until = 0;
			$result[ 'status' ] = 'ok';
			$result[ 'row' ]    = $row;
		}
		else {
			$failures++;
			$lock_until = ( $failures >= BRUTE_GUARD_MAX_FAILURES ) ? $now + BRUTE_GUARD_LOCKOUT : 0;
			$result[ 'status' ] = 'failed';
		}
	}

	ftruncate( $fp, 0 );
	rewind( $fp );
	fwrite( $fp, json_encode( array( 'failures' => $failures, 'lock_until' => $lock_until ) ) );
	fflush( $fp );
	flock( $fp, LOCK_UN );
	fclose( $fp );

	return $result;
}

/*
 * Turns the result of bruteLoginAttempt() into the HTML shown on the page.
 * A wrong password and a locked account get the same message.
 */
function bruteLoginHtml( $result ) {
	if( $result[ 'status' ] == 'ok' ) {
		$user_html = htmlspecialchars( $result[ 'row' ][ 'user' ], ENT_QUOTES, 'UTF-8' );
		$avatar    = htmlspecialchars( $result[ 'row' ][ 'avatar' ], ENT_QUOTES, 'UTF-8' );
		return "<p>Welcome to the password protected area {$user_html}</p><img src=\"{$avatar}\" />";
	}

	$minutes = (int) ( BRUTE_GUARD_LOCKOUT / 60 );
	return "<pre><br />Username and/or password incorrect.<br /><br />Alternatively, the account has been locked because of too many failed logins.<br />If this is the case, <em>please try again in {$minutes} minutes</em>.</pre>";
}
