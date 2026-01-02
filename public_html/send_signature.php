<?php
// send_signature.php

require_once 'includes/config.php';
require_once 'includes/MailHelper.php';

// 1. SECURITY CHECKS
requireAdmin();

// Set JSON Header
header('Content-Type: application/json');

// Allow only POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode(['status' => 'error', 'message' => 'Invalid request']);
    exit;
}

// CSRF Protection
if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
    echo json_encode(['status' => 'error', 'message' => 'Invalid CSRF Token']);
    exit;
}

// Validate IDs
$ids = $_POST['ids'] ?? [];
if (empty($ids) || !is_array($ids)) {
    echo json_encode(['status' => 'error', 'message' => 'No items selected']);
    exit;
}

// 2. PERFORMANCE SETUP
// Increase time limit to 5 minutes for bulk sending
set_time_limit(300);

// Disable output buffering to save memory
if (function_exists('apache_setenv')) {
    @apache_setenv('no-gzip', 1);
}
@ini_set('zlib.output_compression', 0);

// Ensure the log table exists (Optional safety check, good for production)
$db->exec("CREATE TABLE IF NOT EXISTS mail_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    signature_id INTEGER,
    recipient TEXT,
    status TEXT,
    message TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)");

// Initialize results
$results = ['total' => count($ids), 'success' => 0, 'failed' => 0, 'details' => []];

/**
 * Helper function: Load template securely
 */
function getSecureTemplateContent($templateName) {
    $cleanName = basename($templateName);
    if (pathinfo($cleanName, PATHINFO_EXTENSION) !== 'html') {
        return '';
    }
    $path = __DIR__ . '/templates/' . $cleanName;
    return file_exists($path) ? file_get_contents($path) : '';
}

/**
 * Helper function: Sanitize filename
 * Converts "Max Mustermann" to "Max_Mustermann" and removes special chars
 */
function createSafeFilename($userName, $templateName) {
    // Remove accents/umlauts could be complex, simple approach:
    // Replace spaces with underscores
    $safeName = str_replace(' ', '_', $userName);
    // Remove everything that is NOT letters, numbers, underscore or dash
    $safeName = preg_replace('/[^a-zA-Z0-9_\-]/', '', $safeName);
    
    // Combine Name + _ + TemplateName
    return $safeName . '_' . $templateName;
}

// Counter for throttling
$sentCounter = 0;

foreach ($ids as $sig_id) {
    $sig_id = (int)$sig_id;
    
    // 3. PROCESS DATA
    $stmt = $db->prepare("SELECT name, role, email, phone, template FROM user_signatures WHERE id = ?");
    $stmt->bindValue(1, $sig_id, SQLITE3_INTEGER);
    $res = $stmt->execute();
    $data = $res->fetchArray(SQLITE3_ASSOC);

    if (!$data) {
        $results['failed']++;
        continue; // Cannot log if we don't have data
    }

    $recipient = $data['email']; 
    
    // Email Validation
    if (empty($recipient) || !filter_var($recipient, FILTER_VALIDATE_EMAIL)) {
        $msg = "Invalid Email ($recipient)";
        $results['failed']++;
        $results['details'][] = "ID $sig_id: $msg";
        
        // LOG ERROR TO DB
        $log = $db->prepare("INSERT INTO mail_logs (signature_id, recipient, status, message) VALUES (?, ?, 'error', ?)");
        $log->bindValue(1, $sig_id, SQLITE3_INTEGER);
        $log->bindValue(2, $recipient, SQLITE3_TEXT);
        $log->bindValue(3, $msg, SQLITE3_TEXT);
        $log->execute();
        continue;
    }

    // Template Loading
    $rawHtml = getSecureTemplateContent($data['template']);
    if (empty($rawHtml)) {
        $msg = "Template missing/invalid";
        $results['failed']++;
        $results['details'][] = "ID $sig_id: $msg";
        
        // LOG ERROR TO DB
        $log = $db->prepare("INSERT INTO mail_logs (signature_id, recipient, status, message) VALUES (?, ?, 'error', ?)");
        $log->bindValue(1, $sig_id, SQLITE3_INTEGER);
        $log->bindValue(2, $recipient, SQLITE3_TEXT);
        $log->bindValue(3, $msg, SQLITE3_TEXT);
        $log->execute();
        continue;
    }

    $finalHtml = str_replace(
        ['{{NAME}}', '{{ROLE}}', '{{EMAIL}}', '{{PHONE}}'],
        [
            htmlspecialchars($data['name']), 
            htmlspecialchars($data['role']), 
            htmlspecialchars($data['email']), 
            htmlspecialchars($data['phone'])
        ],
        $rawHtml
    );

    // --- NEW: Generate Dynamic Attachment Name ---
    // Example: "John_Doe_signature_default.html"
    $attachmentName = createSafeFilename($data['name'], $data['template']);

    // Assemble email body
    $subject = "Your New Email Signature";
    $body  = "<h3>Hello " . htmlspecialchars($data['name']) . ",</h3>";
    // Show the dynamic name in the text too
    $body .= "<p>Your new signature is attached as <strong>" . htmlspecialchars($attachmentName) . "</strong>.</p>";
    $body .= "<p>Please open the attachment in your browser, copy everything (Ctrl+A, Ctrl+C), and paste it into your email signature settings.</p>";
    $body .= "<hr><h4>Preview:</h4>";
    $body .= "<div style='border:1px dashed #ccc; padding:10px;'>" . $finalHtml . "</div>";

    $attachments = [
        [
            'content' => $finalHtml,
            'name'    => $attachmentName // <--- New Name Here
        ]
    ];

    // 4. SENDING
    $sendResult = MailHelper::send($recipient, $subject, $body, '', false, $attachments);

    // 5. LOG RESULT TO DATABASE
    $status = $sendResult['success'] ? 'success' : 'error';
    $logMsg = $sendResult['message'];

    $log = $db->prepare("INSERT INTO mail_logs (signature_id, recipient, status, message) VALUES (?, ?, ?, ?)");
    $log->bindValue(1, $sig_id, SQLITE3_INTEGER);
    $log->bindValue(2, $recipient, SQLITE3_TEXT);
    $log->bindValue(3, $status, SQLITE3_TEXT);
    $log->bindValue(4, $logMsg, SQLITE3_TEXT);
    $log->execute();

    if ($sendResult['success']) {
        $results['success']++;
        $sentCounter++;
    } else {
        $results['failed']++;
        $results['details'][] = "ID $sig_id: " . $sendResult['message'];
    }

    // 6. THROTTLING
    usleep(500000); 
    if ($sentCounter > 0 && $sentCounter % 10 === 0) {
        sleep(2);
    }
}

// 7. CLEANUP
if (method_exists('MailHelper', 'closeConnection')) {
    MailHelper::closeConnection();
}

echo json_encode(['status' => 'success', 'data' => $results]);
?>
