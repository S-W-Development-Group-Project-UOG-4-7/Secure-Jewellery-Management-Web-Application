<?php
// api/logic/process_delivery.php
error_reporting(0);
header('Content-Type: application/json');
include __DIR__ . '/../../config/db_pg.php';

// GET: Fetch Delivery History & Stock Status (Task 1.2.3 & 1.3.1)
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $deliveries = pg_fetch_all(pg_query($db, "SELECT d.*, s.company_name FROM deliveries d LEFT JOIN suppliers s ON d.supplier_id = s.supplier_id ORDER BY d.delivery_date DESC LIMIT 10"));
    $stock = pg_fetch_all(pg_query($db, "SELECT * FROM jewellery"));
    echo json_encode(["deliveries" => $deliveries ?: [], "stock" => $stock ?: []]);
    exit;
}

// POST: Process New Delivery (Task 2.2 & 2.3)
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $sup_id = $_POST['supplier_id'];
    $type = $_POST['jewellery_type'];
    $qty = (int)$_POST['quantity'];

    // Task 2.2.4: Save Invoice
    $path = null;
    if (isset($_FILES['invoice']) && $_FILES['invoice']['error'] == 0) {
        $dir = __DIR__ . '/../../uploads/invoices/';
        if (!is_dir($dir)) mkdir($dir, 0777, true);
        $name = time() . '_' . $_FILES['invoice']['name'];
        if (move_uploaded_file($_FILES['invoice']['tmp_name'], $dir . $name)) {
            $path = 'uploads/invoices/' . $name;
        }
    }

    // TRANSACTION START
    pg_query($db, "BEGIN");

    try {
        // 1. Create Delivery Record
        $q1 = "INSERT INTO deliveries (supplier_id, jewellery_type, quantity_received, invoice_path) VALUES ($1, $2, $3, $4)";
        $r1 = pg_query_params($db, $q1, [$sup_id, $type, $qty, $path]);
        if (!$r1) throw new Exception("Failed to record delivery.");

        // 2. Update Stock Quantity (Task 2.3.1 & 2.3.2)
        $q2 = "UPDATE jewellery SET current_quantity = current_quantity + $1 WHERE type = $2";
        $r2 = pg_query_params($db, $q2, [$qty, $type]);
        
        // Auto-Insert if item type doesn't exist yet
        if (pg_affected_rows($r2) == 0) {
            pg_query_params($db, "INSERT INTO jewellery (type, current_quantity) VALUES ($1, $2)", [$type, $qty]);
        }

        // 3. Update Supplier Score (Gamification)
        pg_query_params($db, "UPDATE suppliers SET supplier_score = supplier_score + 10 WHERE supplier_id = $1", [$sup_id]);

        // 4. Generate Stock Log (Task 2.3.3)
        $q3 = "INSERT INTO stock_logs (jewellery_type, change_amount, action_type) VALUES ($1, $2, 'DELIVERY')";
        pg_query_params($db, $q3, [$type, $qty]);

        pg_query($db, "COMMIT");
        echo json_encode(["status" => "success", "message" => "Delivery Processed & Stock Updated"]);

    } catch (Exception $e) {
        pg_query($db, "ROLLBACK");
        echo json_encode(["status" => "error", "message" => $e->getMessage()]);
    }
}
?>