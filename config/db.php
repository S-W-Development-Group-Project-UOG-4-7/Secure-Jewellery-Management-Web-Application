<?php
// File: config/db.php

$host = "localhost";
$port = "5432";
$dbname = "jewellery_secure_db"; // Ensure you created this exact DB name in pgAdmin
$user = "postgres";
$password = "2002"; // Your updated password

$conn_string = "host={$host} port={$port} dbname={$dbname} user={$user} password={$password}";

// Attempt connection
$db = pg_connect($conn_string);

if (!$db) {
    die("Error: Could not connect to database. Please check your password in config/db.php");
}
?>