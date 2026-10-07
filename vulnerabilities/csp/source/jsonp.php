<?php
header("Content-Type: application/javascript; charset=UTF-8");
header("X-Content-Type-Options: nosniff");

// The callback ends up being executed as script, so never take it verbatim
// from the request: only the function the page itself uses is allowed.
$callback = "solveSum";

$outp = array ("answer" => "15");

echo $callback . "(".json_encode($outp).")";
?>
