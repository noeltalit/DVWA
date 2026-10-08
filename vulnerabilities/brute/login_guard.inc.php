<?php
/*
 * Login guard for the Brute Force pages.
 *
 * Every login attempt for an account goes through bruteLoginAttempt(), which
 * keeps a failed-attempt counter per (security level, account) on disk:
 *
 *  - after a failed login the account cools down for BRUTE_GUARD_COOLDOWN
 *    seconds, after BRUTE_GUARD_MAX_FAILURES failures it is locked for
 *    BRUTE_GUARD_LOCKOUT seconds;
 *  - while it is cooling down / locked the password is NOT checked at all, so
 *    a guessing run can't find the right password, it only gets the
 *    "account locked" page (a normal 200 page, no sleep() involved);
 *  - attempts made while locked count as failures too;
 *  - a successful login resets the counter.
 *
 * The state file is held under an exclusive lock for the whole
 * check-password-and-record step, so parallel guesses are serialised and
 * can't race past the counter. The account is looked up first and the counter
 * is keyed on the stored user name, so "Admin" or "admin " (which MySQL
 * matches as "admin") share the counter of "admin".
 */

define( 'BRUTE_GUARD_MAX_FAILURES', 3 );
define( 'BRUTE_GUARD_COOLDOWN', 30 );        // seconds after a failed login
define( 'BRUTE_GUARD_LOCKOUT', 15 * 60 );    // seconds after too many failures

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
 * Returns array( 'status' => 'ok' | 'failed' | 'locked', 'row' => user row or null,
 *                'wait' => seconds left before the account can be tried again )
 */
function bruteLoginAttempt( $db, $level, $user, $pass ) {
	$result = array( 'status' => 'failed', 'row' => null, 'wait' => 0 );

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
		$result[ 'wait' ]   = BRUTE_GUARD_COOLDOWN;
		return $result;
	}

	$state = json_decode( stream_get_contents( $fp ), true );
	if( !is_array( $state ) ) {
		$state = array();
	}
	$failures   = isset( $state[ 'failures' ] ) ? intval( $state[ 'failures' ] ) : 0;
	$lock_until = isset( $state[ 'lock_until' ] ) ? intval( $state[ 'lock_until' ] ) : 0;
	$now        = time();

	if( $lock_until > $now ) {
		// Locked: don't even look at the password
		$failures++;
		if( $failures >= BRUTE_GUARD_MAX_FAILURES ) {
			$lock_until = max( $lock_until, $now + BRUTE_GUARD_LOCKOUT );
		}
		$result[ 'status' ] = 'locked';
		$result[ 'wait' ]   = $lock_until - $now;
	}
	else {
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
			$lock_until = $now + ( ( $failures >= BRUTE_GUARD_MAX_FAILURES ) ? BRUTE_GUARD_LOCKOUT : BRUTE_GUARD_COOLDOWN );
			$result[ 'status' ] = 'failed';
			$result[ 'wait' ]   = $lock_until - $now;
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
 */
function bruteLoginHtml( $result ) {
	if( $result[ 'status' ] == 'ok' ) {
		$user_html = htmlspecialchars( $result[ 'row' ][ 'user' ], ENT_QUOTES, 'UTF-8' );
		$avatar    = htmlspecialchars( $result[ 'row' ][ 'avatar' ], ENT_QUOTES, 'UTF-8' );
		return "<p>Welcome to the password protected area {$user_html}</p><img src=\"{$avatar}\" />";
	}

	$minutes = max( 1, (int) ceil( $result[ 'wait' ] / 60 ) );
	if( $result[ 'status' ] == 'locked' ) {
		return "<pre><br />This account has been locked because of too many failed logins.<br /><em>Please try again in {$minutes} minute(s).</em></pre>";
	}
	return "<pre><br />Username and/or password incorrect.<br /><br />To prevent password guessing, the account can't be tried again for a short while after a failed login.</pre>";
}
