<?php
include __DIR__ . '/../db_pg.php';
header('Content-Type: application/json');

$method = $_SERVER['REQUEST_METHOD'];

// LIST USERS (Task 1.3.1)
if ($method === 'GET') {
    $res = pg_query($db, "SELECT * FROM users ORDER BY user_id ASC");
    echo json_encode(pg_fetch_all($res) ?: []);
}

// ADD NEW USER (Task 2.3.1)
if ($method === 'POST') {
    $data = json_decode(file_get_contents("php://input"), true);
    $q = "INSERT INTO users (username, email, role) VALUES ($1, $2, $3)";
    $res = pg_query_params($db, $q, [$data['username'], $data['email'], $data['role']]);
    echo json_encode(["status" => $res ? "success" : "error"]);
}

// UPDATE ROLE (Task 2.3.2)
if ($method === 'PUT') {
    $data = json_decode(file_get_contents("php://input"), true);
    $q = "UPDATE users SET role = $1 WHERE user_id = $2";
    $res = pg_query_params($db, $q, [$data['role'], $data['user_id']]);
    echo json_encode(["status" => $res ? "success" : "error"]);
}

// TOGGLE ACTIVATE/DEACTIVATE (Task 1.3.4 & 2.3.3)
if ($method === 'PATCH') {
    $data = json_decode(file_get_contents("php://input"), true);
    // Reads current status and flips it (NOT is_active)
    $q = "UPDATE users SET is_active = NOT is_active WHERE user_id = $1";
    $res = pg_query_params($db, $q, [$data['user_id']]);
    echo json_encode(["status" => $res ? "success" : "error"]);
}
?>