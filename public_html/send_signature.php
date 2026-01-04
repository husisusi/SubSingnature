<?php
// send_signature.php
// PRODUCTION READY - SECURITY PRIO 1

require_once 'includes/config.php';
require_once 'includes/MailHelper.php';

// ---------------------------------------------------------
// 1. SECURITY & CONFIGURATION
// ---------------------------------------------------------
requireAdmin(); // Only Admins allowed

// Disable output buffering for Real-Time Streaming (SSE)
if (function_exists('apache_setenv')) {
    @apache_setenv('no-gzip', 1);
}
@ini_set('zlib.output_compression', 0);
@ini_set('implicit_flush', 1);
while (ob_get_level() > 0) {
    ob_end_clean();
}

// Set Headers for Server-Sent Events
header('Content-Type: text/event-stream');
header('Cache-Control: no-cache');
header('Connection: keep-alive');

// ---------------------------------------------------------
// 2. INPUT VALIDATION
// ---------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    sendStreamResponse('fatal_error', 'Invalid request method.');
    exit;
}

// CSRF Protection
if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
    sendStreamResponse('fatal_error', 'Invalid CSRF Token.');
    exit;
}

// Validate IDs
$ids = $_POST['ids'] ?? [];
if (empty($ids) || !is_array($ids)) {
    sendStreamResponse('fatal_error', 'No items selected.');
    exit;
}

// Increase time limit for bulk sending (5 minutes)
set_time_limit(300);

// Initialize stats
$total = count($ids);
$successCount = 0;
$failCount = 0;
$processed = 0;

// ---------------------------------------------------------
// 3. HELPER FUNCTIONS
// ---------------------------------------------------------

/**
 * Sends a JSON chunk to the browser for the progress bar.
 */
function sendStreamResponse($status, $message, $progress = null) {
    $data = [
        'status' => $status,
        'message' => $message,
        'progress' => $progress
    ];
    echo "data: " . json_encode($data) . "\n\n";
    flush(); 
}

/**
 * Loads the main email body template.
 * Looks for 'templates/email_notification.html'.
 * Falls back to a default string if missing.
 */
function getEmailBodyTemplate() {
    $path = __DIR__ . '/templates/email_notification.html';
    
    // Security: Hardcoded path prevents directory traversal
    if (file_exists($path)) {
        return file_get_contents($path);
    }
    
    // Fallback content
    return "<p>Hello {{NAME}},</p>
            <p>Your new signature is attached as <strong>{{ATTACHMENT_NAME}}</strong>.</p>
            <hr>
            {{PREVIEW}}";
}

/**
 * Loads a signature template securely.
 */
function getSecureTemplateContent($templateName) {
    $cleanName = basename($templateName); // Security: Prevent traversal
    if (pathinfo($cleanName, PATHINFO_EXTENSION) !== 'html') {
        return '';
    }
    $path = __DIR__ . '/templates/' . $cleanName;
    return file_exists($path) ? file_get_contents($path) : '';
}

/**
 * Creates a safe filename for the attachment.
 */
function createSafeFilename($userName, $templateName) {
    $safeName = str_replace(' ', '_', $userName);
    $safeName = preg_replace('/[^a-zA-Z0-9_\-]/', '', $safeName);
    return $safeName . '_' . $templateName;
}

// ---------------------------------------------------------
// 4. PREPARATION
// ---------------------------------------------------------

// Load the Email Body Template ONCE (Performance)
$emailBodyTemplate = getEmailBodyTemplate();

// ---------------------------------------------------------
// 5. PROCESSING LOOP
// ---------------------------------------------------------

foreach ($ids as $sig_id) {
    
    // --- CRITICAL SECURITY: PANIC BUTTON CHECK ---
    // If user clicks "STOP IMMEDIATELY", browser closes connection.
    // We detect this and exit the script instantly.
    if (connection_aborted()) {
        exit; // Hard stop
    }
    
    $processed++;
    $sig_id = (int)$sig_id; // Security: Force Integer

    // Fetch User Data
    $stmt = $db->prepare("SELECT name, role, email, phone, template FROM user_signatures WHERE id = ?");
    $stmt->bindValue(1, $sig_id, SQLITE3_INTEGER);
    $res = $stmt->execute();
    $data = $res->fetchArray(SQLITE3_ASSOC);

    $progData = ['current' => $processed, 'total' => $total];

    // Check if signature exists
    if (!$data) {
        $failCount++;
        sendStreamResponse('error', "ID $sig_id: Signature not found.", $progData);
        continue;
    }

    $recipient = $data['email'];

    // Validate Email
    if (empty($recipient) || !filter_var($recipient, FILTER_VALIDATE_EMAIL)) {
        $failCount++;
        $msg = "ID $sig_id: Invalid Email ($recipient)";
        
        // Log Error to DB
        $db->exec("INSERT INTO mail_logs (signature_id, recipient, status, message) VALUES ($sig_id, '$recipient', 'error', '$msg')");
        
        sendStreamResponse('error', $msg, $progData);
        continue;
    }

    // Load Signature HTML Template
    $rawHtml = getSecureTemplateContent($data['template']);
    if (empty($rawHtml)) {
        $failCount++;
        $msg = "ID $sig_id: Template file missing ($data[template])";
        
        // Log Error to DB
        $db->exec("INSERT INTO mail_logs (signature_id, recipient, status, message) VALUES ($sig_id, '$recipient', 'error', '$msg')");
        
        sendStreamResponse('error', $msg, $progData);
        continue;
    }

    // Replace Placeholders in Signature HTML
    $finalSigHtml = str_replace(
        ['{{NAME}}', '{{ROLE}}', '{{EMAIL}}', '{{PHONE}}'],
        [
            htmlspecialchars($data['name']), 
            htmlspecialchars($data['role']), 
            htmlspecialchars($data['email']), 
            htmlspecialchars($data['phone'])
        ],
        $rawHtml
    );

    $attachmentName = createSafeFilename($data['name'], $data['template']);

    // ------------------------------------------------------------------
    // BUILD EMAIL BODY
    // ------------------------------------------------------------------
    
    // Create a visual preview block for the email body
    $previewBlock = "<div style='border:1px dashed #ccc; padding:15px; margin-top:10px; background:#fff;'>" . $finalSigHtml . "</div>";
    
    // Inject data into the Email Body Template
    $mailBody = str_replace(
        ['{{NAME}}', '{{ATTACHMENT_NAME}}', '{{PREVIEW}}'],
        [
            htmlspecialchars($data['name']),
            htmlspecialchars($attachmentName),
            $previewBlock
        ],
        $emailBodyTemplate
    );

    $subject = "Your New Email Signature"; 
    
    // Prepare Attachment
    $attachments = [
        [
            'content' => $finalSigHtml,
            'name'    => $attachmentName
        ]
    ];

    // SEND MAIL via Helper
    $sendResult = MailHelper::send($recipient, $subject, $mailBody, '', false, $attachments);

    // LOG RESULT TO DATABASE
    $status = $sendResult['success'] ? 'success' : 'error';
    $logMsg = $db->escapeString($sendResult['message']);
    
    $logSql = "INSERT INTO mail_logs (signature_id, recipient, status, message) VALUES ($sig_id, '$recipient', '$status', '$logMsg')";
    $db->exec($logSql);

    if ($sendResult['success']) {
        $successCount++;
        sendStreamResponse('success', "Sent to: $recipient", $progData);
    } else {
        $failCount++;
        sendStreamResponse('error', "Failed: $recipient (" . $sendResult['message'] . ")", $progData);
    }

    // THROTTLING (Anti-Spam protection)
    // 0.5s pause per mail
    usleep(500000); 
    // Additional 2s pause every 10 mails
    if ($successCount > 0 && $successCount % 10 === 0) {
        sleep(2);
    }
}

// ---------------------------------------------------------
// 6. FINISH
// ---------------------------------------------------------
if (method_exists('MailHelper', 'closeConnection')) {
    MailHelper::closeConnection();
}

$summary = "Finished! Success: $successCount, Failed: $failCount";
$finalData = [
    'status' => 'finished',
    'summary' => $summary,
    'progress' => ['current' => $total, 'total' => $total]
];
echo "data: " . json_encode($finalData) . "\n\n";
flush();
?>
