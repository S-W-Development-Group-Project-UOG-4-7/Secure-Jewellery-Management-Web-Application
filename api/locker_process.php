<?php
include __DIR__ . '/../db_pg.php';
header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    
    $jewellery_id = $_POST['jewellery_id'];
    $type = $_POST['verification_type']; // 'BEFORE_STORAGE' or 'AFTER_STORAGE'
    $notes = $_POST['notes'];
    
    // 2.2 Task 4: Save Verification Images
    $file_path = null;
    if (isset($_FILES['proof_image']) && $_FILES['proof_image']['error'] == 0) {
        $dir = __DIR__ . '/../uploads/locker/';
        if (!is_dir($dir)) mkdir($dir, 0777, true);
        $name = time() . '_' . basename($_FILES['proof_image']['name']);
        if (move_uploaded_file($_FILES['proof_image']['tmp_name'], $dir . $name)) {
            $file_path = 'uploads/locker/' . $name;
        }
    }

    pg_query($db, "BEGIN"); // Start Transaction

    try {
        // 1. Insert Verification Record (2.2 Task 1)
        $q1 = "INSERT INTO locker_verifications (jewellery_id, verification_type, proof_image_path, notes) VALUES ($1, $2, $3, $4)";
        $r1 = pg_query_params($db, $q1, [$jewellery_id, $type, $file_path, $notes]);

        if (!$r1) throw new Exception("Verification failed.");

        // 2. Update Jewellery Status (2.2 Task 2 & 3 Handler Logic)
        $new_status = ($type === 'BEFORE_STORAGE') ? 'IN_LOCKER' : 'ON_DISPLAY';
        $q2 = "UPDATE jewellery SET status = $1 WHERE jewellery_id = $2";
        pg_query_params($db, $q2, [$new_status, $jewellery_id]);

        pg_query($db, "COMMIT");
        echo json_encode(["status" => "success", "message" => "Locker Verification Completed: " . $new_status]);

    } catch (Exception $e) {
        pg_query($db, "ROLLBACK");
        echo json_encode(["status" => "error", "message" => $e->getMessage()]);
    }
}

// GET Verification History (For Task 1.2.4 Verification Results UI)
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $jid = $_GET['jewellery_id'];
    $res = pg_query_params($db, "SELECT * FROM locker_verifications WHERE jewellery_id = $1 ORDER BY verification_date DESC", [$jid]);
    echo json_encode(pg_fetch_all($res) ?: []);
}
?>