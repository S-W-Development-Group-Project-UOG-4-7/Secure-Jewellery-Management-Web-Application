<?php
// api/auth_register.php
include __DIR__ . '/../../config/db_pg.php';
header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $data = json_decode(file_get_contents("php://input"), true);
    
    // Basic validation
    if (empty($data['username']) || empty($data['email']) || empty($data['password'])) {
        echo json_encode(["status" => "error", "message" => "All fields required."]);
        exit;
    }

    // --- SECURITY NOTE ---
    // In a live system, the password MUST be hashed and stored: 
    // $passwordHash = password_hash($data['password'], PASSWORD_DEFAULT);
    
    $defaultRole = 'Customer'; 
    $isActive = 'TRUE';
    
    // WARNING: In this prototype, we don't store the password field securely. 
    // For a real system, ensure password hashing and storage.
    $query = "INSERT INTO users (username, email, role, is_active) VALUES ($1, $2, $3, $4)";
    $result = pg_query_params($db, $query, [$data['username'], $data['email'], $defaultRole, $isActive]);

    if ($result) {
        echo json_encode(["status" => "success", "message" => "Registration successful. Please log in."]);
    } else {
        echo json_encode(["status" => "error", "message" => "Registration failed. Username or Email may be taken."]);
    }
}
?>