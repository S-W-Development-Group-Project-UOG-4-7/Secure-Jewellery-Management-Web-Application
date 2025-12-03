<?php
include __DIR__ . '/../db_pg.php';
header('Content-Type: application/json');

$method = $_SERVER['REQUEST_METHOD'];

// LIST (Task 1.1.1)
if ($method === 'GET') {
    $result = pg_query($db, "SELECT * FROM jewellery ORDER BY jewellery_id DESC");
    echo json_encode(pg_fetch_all($result) ?: []);
}

// ADD (Task 2.1.2)
if ($method === 'POST') {
    $data = json_decode(file_get_contents("php://input"), true);
    $q = "INSERT INTO jewellery (name, type, material, weight_grams, price) VALUES ($1, $2, $3, $4, $5)";
    $res = pg_query_params($db, $q, [$data['name'], $data['type'], $data['material'], $data['weight'], $data['price']]);
    echo json_encode(["status" => $res ? "success" : "error"]);
}

// UPDATE (Task 2.1.3)
if ($method === 'PUT') {
    $data = json_decode(file_get_contents("php://input"), true);
    $q = "UPDATE jewellery SET name=$1, type=$2, material=$3, weight_grams=$4, price=$5 WHERE jewellery_id=$6";
    $res = pg_query_params($db, $q, [$data['name'], $data['type'], $data['material'], $data['weight'], $data['price'], $data['id']]);
    echo json_encode(["status" => $res ? "success" : "error"]);
}

// DELETE (Task 2.1.4)
if ($method === 'DELETE') {
    $id = $_GET['id'];
    $res = pg_query_params($db, "DELETE FROM jewellery WHERE jewellery_id = $1", [$id]);
    echo json_encode(["status" => $res ? "success" : "error"]);
}
?>