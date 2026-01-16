<?php 
include '../inc/functions.php';
$ip = $_GET['ip']; 
echo $ip." ";

$result = blockConnectionForIP($ip);

echo $result['ip']." "." ";
echo $result['error']." ";
echo $result['message']." ";
echo $result['output']." ";
echo $result['returnCode']." ";
echo $result['success']." ";