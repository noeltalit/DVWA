<?php
define( 'DVWA_WEB_PAGE_TO_ROOT', '../../' );
require_once DVWA_WEB_PAGE_TO_ROOT . 'dvwa/includes/dvwaPage.inc.php';

dvwaDatabaseConnect();

header ("Content-Type: application/json");

/*
Only the admin is allowed to change the data, whatever the security level.
*/
if (dvwaCurrentUser() != "admin") {
	http_response_code(403);
	print json_encode (array ("result" => "fail", "error" => "Access denied"));
	exit;
}

if ($_SERVER['REQUEST_METHOD'] != "POST") {
	$result = array (
						"result" => "fail",
						"error" => "Only POST requests are accepted"
					);
	echo json_encode($result);
	exit;
}

// A cross site HTML form can't send JSON, only a script on this site can
$content_type = isset ($_SERVER['CONTENT_TYPE']) ? strtolower (trim (explode (";", $_SERVER['CONTENT_TYPE'])[0])) : "";
if ($content_type != "application/json") {
	$result = array (
						"result" => "fail",
						"error" => "Only JSON requests are accepted"
					);
	echo json_encode($result);
	exit;
}

$json = file_get_contents('php://input');
$data = json_decode($json);
if (!is_object ($data) ||
	!isset ($data->id, $data->first_name, $data->surname) ||
	!is_scalar ($data->id) || !ctype_digit ((string) $data->id) ||
	!is_string ($data->first_name) || !is_string ($data->surname)) {
	$result = array (
						"result" => "fail",
						"error" => 'Invalid format, expecting "{id: {user ID}, first_name: "{first name}", surname: "{surname}"}'

					);
	echo json_encode($result);
	exit;
}

$id = intval ($data->id);
$first_name = mb_substr ($data->first_name, 0, 15, 'UTF-8');
$surname = mb_substr ($data->surname, 0, 15, 'UTF-8');

$stmt = $db->prepare ('UPDATE users SET first_name = (:first_name), last_name = (:surname) WHERE user_id = (:id);');
$stmt->bindParam (':first_name', $first_name, PDO::PARAM_STR);
$stmt->bindParam (':surname', $surname, PDO::PARAM_STR);
$stmt->bindParam (':id', $id, PDO::PARAM_INT);
$stmt->execute ();

print json_encode (array ("result" => "ok"));
exit;
?>
