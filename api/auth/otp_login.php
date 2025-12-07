<?php
// api/auth/otp_login.php

// 1. SETUP
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

session_start();
header('Content-Type: application/json');
error_reporting(0);

// 2. CONNECT DATABASE
include __DIR__ . '/../../config/db_pg.php';

// 3. LOAD PHPMAILER
require __DIR__ . '/../../libs/PHPMailer/Exception.php';
require __DIR__ . '/../../libs/PHPMailer/PHPMailer.php';
require __DIR__ . '/../../libs/PHPMailer/SMTP.php';

// --- CONFIGURATION (EDIT THIS!) ---
define('SMTP_HOST', 'smtp.gmail.com');
define('SMTP_USER', 'kokiladulshan021@gmail.com');   // <--- ENTER YOUR GMAIL
define('SMTP_PASS', 'sauw dqjk udzw rmyn');    // <--- ENTER YOUR APP PASSWORD

// --- EMAIL FUNCTION ---
function send_email_otp($username, $email, $otp) {
    $mail = new PHPMailer(true);
    try {
        $mail->isSMTP();
        $mail->Host       = SMTP_HOST;
        $mail->SMTPAuth   = true;
        $mail->Username   = SMTP_USER;
        $mail->Password   = SMTP_PASS;
        $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
        $mail->Port       = 587;

        $mail->setFrom(SMTP_USER, 'SJM Security');
        $mail->addAddress($email, $username);

        $mail->isHTML(true);
        $mail->Subject = 'SJM Login Code: ' . $otp;
        $mail->Body    = "
            <div style='font-family: Arial, sans-serif; padding: 20px; background: #f4f4f4;'>
                <div style='max-width: 400px; margin: 0 auto; background: #fff; padding: 30px; border-radius: 8px; border-top: 4px solid #d4af37;'>
                    <h2 style='color: #333; margin-top: 0;'>Secure Access</h2>
                    <p>Hello <strong>$username</strong>,</p>
                    <p>Use this One-Time Password to complete your login:</p>
                    <div style='font-size: 28px; font-weight: bold; letter-spacing: 5px; color: #d4af37; margin: 20px 0; text-align: center;'>$otp</div>
                    <p style='color: #777; font-size: 12px; text-align: center;'>Valid for 5 minutes.</p>
                </div>
            </div>";
        
        $mail->send();
        return true;
    } catch (Exception $e) {
        error_log("Mailer Error: " . $mail->ErrorInfo);
        return false;
    }
}

$input = json_decode(file_get_contents("php://input"), true);
$action = $input['action'] ?? '';

// --- ACTION 1: SEND OTP ---
if ($action === 'send_otp') {
    $user = trim($input['username']);
    $pass = $input['password'];

    $query = "SELECT user_id, email, password_hash, role, is_active FROM users WHERE username = $1";
    $result = pg_query_params($db, $query, [$user]);

    if ($result && pg_num_rows($result) > 0) {
        $row = pg_fetch_assoc($result);

        if ($row['is_active'] === 'f') {
            echo json_encode(["status" => "error", "message" => "Account Deactivated"]);
            exit;
        }

        if (password_verify($pass, $row['password_hash'])) {
            $otp = rand(100000, 999999);
            
            // Save to DB
            pg_query_params($db, 
                "UPDATE users SET otp_code = $1, otp_expiry = (NOW() + interval '5 minutes') WHERE user_id = $2", 
                [$otp, $row['user_id']]
            );

            // SEND REAL EMAIL
            if (send_email_otp($user, $row['email'], $otp)) {
                echo json_encode([
                    "status" => "success", 
                    "message" => "OTP Sent to " . $row['email']
                ]);
            } else {
                echo json_encode(["status" => "error", "message" => "Email failed. Check server logs."]);
            }
        } else {
            echo json_encode(["status" => "error", "message" => "Incorrect Password"]);
        }
    } else {
        echo json_encode(["status" => "error", "message" => "User Not Found"]);
    }
}

// --- ACTION 2: VERIFY OTP ---
if ($action === 'verify_otp') {
    $user = trim($input['username']);
    $otp = trim($input['otp']);

    $query = "SELECT user_id, role FROM users WHERE username = $1 AND otp_code = $2 AND otp_expiry > NOW()";
    $result = pg_query_params($db, $query, [$user, $otp]);

    if ($result && pg_num_rows($result) > 0) {
        $row = pg_fetch_assoc($result);
        
        pg_query_params($db, "UPDATE users SET otp_code = NULL WHERE user_id = $1", [$row['user_id']]);
        
        $_SESSION['user_id'] = $row['user_id'];
        $_SESSION['role'] = $row['role'];
        $_SESSION['username'] = $user;

        $redirect = ($row['role'] === 'Admin') ? 'pages/admin_portal.html' : 'pages/design_studio.php';
        
        echo json_encode(["status" => "success", "redirect" => $redirect]);
    } else {
        echo json_encode(["status" => "error", "message" => "Invalid or Expired OTP"]);
    }
}
?>