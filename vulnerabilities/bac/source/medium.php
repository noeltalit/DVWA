<?php
if (!defined('DVWA_WEB_PAGE_TO_ROOT')) {
    define('DVWA_WEB_PAGE_TO_ROOT', '../../../');
}

// Work out who is asking from the logged in session only. Nothing the client
// sends (cookies, tokens, request parameters) decides who they are.
$query = "SELECT user_id FROM users WHERE user = ? LIMIT 1";
$stmt = mysqli_prepare($GLOBALS["___mysqli_ston"], $query);
$currentUser = dvwaCurrentUser();
mysqli_stmt_bind_param($stmt, "s", $currentUser);
mysqli_stmt_execute($stmt);
$result = mysqli_stmt_get_result($stmt);
$user_info = ($result && mysqli_num_rows($result) > 0) ? mysqli_fetch_assoc($result) : ['user_id' => 0];
$current_user_id = intval($user_info['user_id']);
mysqli_stmt_close($stmt);

$html = "";
if (isset($_GET['action']) && isset($_GET['user_id'])) {
    if (!is_string($_GET['user_id']) || !preg_match('/^\d+\z/', $_GET['user_id'])) {
        $html .= "<p>Invalid user ID format. Please enter a number.</p>";
    } else {
        $id = intval($_GET['user_id']);

        // Users may only ever see their own profile
        if ($current_user_id === 0 || $id !== $current_user_id) {
            $html .= "<p>Access denied. You can only view your own profile.</p>";
        } else {
            $query = "SELECT first_name, last_name, user_id, avatar FROM users WHERE user_id = ? LIMIT 1";
            $stmt = mysqli_prepare($GLOBALS["___mysqli_ston"], $query);
            mysqli_stmt_bind_param($stmt, "i", $id);
            mysqli_stmt_execute($stmt);
            $result = mysqli_stmt_get_result($stmt);

            if ($result && mysqli_num_rows($result) > 0) {
                $row = mysqli_fetch_assoc($result);
                $html .= "
                    <div class=\"profile-info\">
                        <h3>User Profile</h3>
                        <p>User ID: " . htmlspecialchars($row['user_id'], ENT_QUOTES, 'UTF-8') . "</p>
                        <p>Name: " . htmlspecialchars($row['first_name'], ENT_QUOTES, 'UTF-8') . " " .
                    htmlspecialchars($row['last_name'], ENT_QUOTES, 'UTF-8') . "</p>
                        <p>Avatar: " . htmlspecialchars($row['avatar'], ENT_QUOTES, 'UTF-8') . "</p>
                    </div>";
            } else {
                $html .= "<p>No user found with ID: {$id}</p>";
            }
            mysqli_stmt_close($stmt);
        }

        // Log the access attempt. Only trust the address of the connection,
        // headers such as X-Forwarded-For are set by the client.
        try {
            $ip = $_SERVER['REMOTE_ADDR'];
            $log_query = "INSERT INTO bac_log (user_id, target_id, ip_address) VALUES (?, ?, ?)";
            $log_stmt = mysqli_prepare($GLOBALS["___mysqli_ston"], $log_query);
            mysqli_stmt_bind_param($log_stmt, "iis", $current_user_id, $id, $ip);
            mysqli_stmt_execute($log_stmt);
            mysqli_stmt_close($log_stmt);
        } catch (Exception $e) {
            // Silently fail if logging doesn't work
        }
    }
}
?>
