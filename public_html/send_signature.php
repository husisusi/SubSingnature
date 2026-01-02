<?php
// send_signature.php

require_once 'includes/config.php';
require_once 'includes/MailHelper.php';

// 1. SECURITY CHECKS
requireAdmin();

// WICHTIG: Output Buffering komplett deaktivieren für Live-Streaming
if (function_exists('apache_setenv')) {
    @apache_setenv('no-gzip', 1);
}
@ini_set('zlib.output_compression', 0);
@ini_set('implicit_flush', 1);
while (ob_get_level() > 0) {
    ob_end_clean();
}

// Header für Server-Sent Events (SSE) setzen
header('Content-Type: text/event-stream');
header('Cache-Control: no-cache');
header('Connection: keep-alive');
header('X-Accel-Buffering: no'); // Speziell für Nginx

// WICHTIG: Erlaubt dem Skript zu erkennen, ob der User abgebrochen hat
ignore_user_abort(false);

// Helper Funktion für JSON-Datenstrom
function sendMsg($id, $msg, $progress = null, $status = 'processing') {
    echo "data: " . json_encode([
        'id' => $id, 
        'message' => $msg, 
        'progress' => $progress,
        'status' => $status
    ]) . "\n\n";
    flush(); // Zwingt PHP, die Daten sofort zu senden
}

// Nur POST erlaubt (sicherer für Aktionen)
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    sendMsg(0, 'Invalid request method', null, 'fatal_error');
    exit;
}

// CSRF Schutz
if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
    sendMsg(0, 'Invalid CSRF Token', null, 'fatal_error');
    exit;
}

// IDs validieren
$ids = $_POST['ids'] ?? [];
if (empty($ids) || !is_array($ids)) {
    sendMsg(0, 'No items selected', null, 'fatal_error');
    exit;
}

// 2. PERFORMANCE & DB SETUP
set_time_limit(300); // 5 Minuten Limit

// Log-Tabelle sicherstellen
$db->exec("CREATE TABLE IF NOT EXISTS mail_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    signature_id INTEGER,
    recipient TEXT,
    status TEXT,
    message TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)");

// Helper: Template laden
function getSecureTemplateContent($templateName) {
    $cleanName = basename($templateName);
    if (pathinfo($cleanName, PATHINFO_EXTENSION) !== 'html') return '';
    $path = __DIR__ . '/templates/' . $cleanName;
    return file_exists($path) ? file_get_contents($path) : '';
}

// Helper: Sicherer Dateiname für Anhang
function createSafeFilename($userName, $templateName) {
    $safeName = str_replace(' ', '_', $userName);
    $safeName = preg_replace('/[^a-zA-Z0-9_\-]/', '', $safeName);
    return $safeName . '_' . $templateName;
}

$total = count($ids);
$current = 0;
$successCount = 0;
$failCount = 0;

// Start-Signal
sendMsg(0, 'Starting process...', ['current' => 0, 'total' => $total], 'start');

foreach ($ids as $sig_id) {
    // --- SICHERHEITS-ABBRUCH ---
    // Prüft vor jeder Mail, ob der User die Verbindung getrennt hat (Cancel Button)
    if (connection_aborted()) {
        // Optional: Loggen, dass abgebrochen wurde
        error_log("Mass mail sending aborted by admin (User ID: " . $_SESSION['user_id'] . ")");
        exit; // Skript stirbt hier sofort
    }
    // ---------------------------

    $current++;
    $sig_id = (int)$sig_id;

    // 3. DATEN LADEN
    $stmt = $db->prepare("SELECT name, role, email, phone, template FROM user_signatures WHERE id = ?");
    $stmt->bindValue(1, $sig_id, SQLITE3_INTEGER);
    $res = $stmt->execute();
    $data = $res->fetchArray(SQLITE3_ASSOC);

    if (!$data) {
        $failCount++;
        sendMsg($sig_id, "ID $sig_id not found", ['current' => $current, 'total' => $total], 'error');
        continue;
    }

    $recipient = $data['email'];

    // Validierung
    if (empty($recipient) || !filter_var($recipient, FILTER_VALIDATE_EMAIL)) {
        $failCount++;
        $log = $db->prepare("INSERT INTO mail_logs (signature_id, recipient, status, message) VALUES (?, ?, 'error', ?)");
        $log->bindValue(1, $sig_id, SQLITE3_INTEGER);
        $log->bindValue(2, $recipient, SQLITE3_TEXT);
        $log->bindValue(3, 'Invalid Email', SQLITE3_TEXT);
        $log->execute();
        sendMsg($sig_id, "Invalid Email: $recipient", ['current' => $current, 'total' => $total], 'error');
        continue;
    }

    // Template verarbeiten
    $rawHtml = getSecureTemplateContent($data['template']);
    if (empty($rawHtml)) {
        $failCount++;
        sendMsg($sig_id, "Template missing for $recipient", ['current' => $current, 'total' => $total], 'error');
        continue;
    }

    $finalHtml = str_replace(
        ['{{NAME}}', '{{ROLE}}', '{{EMAIL}}', '{{PHONE}}'],
        [htmlspecialchars($data['name']), htmlspecialchars($data['role']), htmlspecialchars($data['email']), htmlspecialchars($data['phone'])],
        $rawHtml
    );

    $attachmentName = createSafeFilename($data['name'], $data['template']);
    
    // E-Mail Body
    $subject = "Your New Email Signature";
    $body  = "<h3>Hello " . htmlspecialchars($data['name']) . ",</h3>";
    $body .= "<p>Your new signature is attached as <strong>" . htmlspecialchars($attachmentName) . "</strong>.</p>";
    $body .= "<p>Please open the attachment in your browser, copy everything (Ctrl+A, Ctrl+C), and paste it into your email signature settings.</p>";
    $body .= "<hr><h4>Preview:</h4><div style='border:1px dashed #ccc; padding:10px;'>" . $finalHtml . "</div>";

    $attachments = [[ 'content' => $finalHtml, 'name' => $attachmentName ]];

    // 4. SENDEN
    $sendResult = MailHelper::send($recipient, $subject, $body, '', false, $attachments);
    
    // DB Log
    $status = $sendResult['success'] ? 'success' : 'error';
    $log = $db->prepare("INSERT INTO mail_logs (signature_id, recipient, status, message) VALUES (?, ?, ?, ?)");
    $log->bindValue(1, $sig_id, SQLITE3_INTEGER);
    $log->bindValue(2, $recipient, SQLITE3_TEXT);
    $log->bindValue(3, $status, SQLITE3_TEXT);
    $log->bindValue(4, $sendResult['message'], SQLITE3_TEXT);
    $log->execute();

    if ($sendResult['success']) {
        $successCount++;
        sendMsg($sig_id, "Sent to $recipient", ['current' => $current, 'total' => $total], 'success');
    } else {
        $failCount++;
        sendMsg($sig_id, "Failed $recipient: " . $sendResult['message'], ['current' => $current, 'total' => $total], 'error');
    }

    // THROTTLING (Spam-Schutz)
    usleep(500000); // 0.5 Sekunden Pause pro Mail
    if ($current % 10 === 0) {
        sleep(2); // Extra Pause alle 10 Mails
    }
}

// 5. CLEANUP
if (method_exists('MailHelper', 'closeConnection')) {
    MailHelper::closeConnection();
}

// Abschluss-Nachricht
echo "data: " . json_encode([
    'status' => 'finished',
    'summary' => "Completed. Success: $successCount, Failed: $failCount"
]) . "\n\n";
flush();
?>
