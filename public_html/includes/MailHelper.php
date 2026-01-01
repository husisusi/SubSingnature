<?php
// includes/MailHelper.php

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;
use PHPMailer\PHPMailer\SMTP;

require_once __DIR__ . '/config.php';

// Adjust path based on your structure
if (file_exists(__DIR__ . '/PHPMailer/src/PHPMailer.php')) {
    require_once __DIR__ . '/PHPMailer/src/Exception.php';
    require_once __DIR__ . '/PHPMailer/src/PHPMailer.php';
    require_once __DIR__ . '/PHPMailer/src/SMTP.php';
} else {
    require_once __DIR__ . '/PHPMailer/Exception.php';
    require_once __DIR__ . '/PHPMailer/PHPMailer.php';
    require_once __DIR__ . '/PHPMailer/SMTP.php';
}

class MailHelper {
    private static $mailerInstance = null;

    /**
     * Send email securely.
     */
    public static function send($toRecipient, $subject, $bodyHTML, $bodyText = '', $enableDebug = false, $attachments = []) {
        global $db;
        $debugOutput = "";

        try {
            // Singleton Pattern for performance (SMTP Keep-Alive)
            if (self::$mailerInstance === null) {
                // 1. Fetch Settings (fetch only once)
                $settings = [];
                $stmt = $db->prepare("SELECT setting_key, setting_value FROM system_settings WHERE setting_key LIKE 'smtp_%'");
                $result = $stmt->execute();
                while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
                    $settings[$row['setting_key']] = $row['setting_value'];
                }

                if (empty($settings['smtp_host'])) {
                    return ['success' => false, 'message' => 'SMTP Host missing.', 'debug_log' => ''];
                }

                $mail = new PHPMailer(true);
                $mail->isSMTP();
                $mail->Host       = $settings['smtp_host'];
                $mail->SMTPAuth   = (!isset($settings['smtp_auth']) || $settings['smtp_auth'] == '1');
                
                if ($mail->SMTPAuth) {
                    $mail->Username = $settings['smtp_user'];
                    $mail->Password = $settings['smtp_pass'] ?? '';
                }

                $secureMode = $settings['smtp_secure'] ?? 'tls';
                if ($secureMode === 'none') {
                    $mail->SMTPAutoTLS = false; 
                    $mail->SMTPSecure = false;
                } else {
                    $mail->SMTPSecure = $secureMode;
                }

                $mail->Port       = intval($settings['smtp_port'] ?? 587);
                $mail->CharSet    = 'UTF-8';
                $mail->Timeout    = 15;
                $mail->SMTPKeepAlive = true; // IMPORTANT for bulk sending

                // Set Sender
                $fromEmail = $settings['smtp_from_email'] ?? $settings['smtp_user'];
                if (empty($fromEmail)) $fromEmail = 'noreply@' . ($_SERVER['SERVER_NAME'] ?? 'localhost');
                $fromName  = $settings['smtp_from_name']  ?? 'SubSignature System';
                $mail->setFrom($fromEmail, $fromName);

                self::$mailerInstance = $mail;
            }

            $mail = self::$mailerInstance;

            // 2. Configure debugging securely
            if ($enableDebug) {
                $mail->SMTPDebug = SMTP::DEBUG_CONNECTION; // Level 2
                $mail->Debugoutput = function($str, $level) use (&$debugOutput) {
                    // SECURITY: Remove passwords from log
                    $cleanStr = preg_replace('/(PASS\s+)[^\s]+/', '$1 *****', $str); 
                    $cleanStr = preg_replace('/(auth\s+login\s+)[^\s]+/i', '$1 [HIDDEN]', $cleanStr);
                    $debugOutput .= "[$level] $cleanStr\n";
                };
            } else {
                $mail->SMTPDebug = 0;
            }

            // 3. Reset Recipients & Content (Important for reuse)
            $mail->clearAddresses();
            $mail->clearAttachments();
            $mail->clearCustomHeaders();
            
            $mail->addAddress($toRecipient);
            $mail->isHTML(true);
            $mail->Subject = $subject;
            $mail->Body    = $bodyHTML;
            $mail->AltBody = !empty($bodyText) ? $bodyText : strip_tags($bodyHTML);

            // 4. Attachments
            if (!empty($attachments) && is_array($attachments)) {
                foreach ($attachments as $att) {
                    if (isset($att['content']) && isset($att['name'])) {
                        $mail->addStringAttachment($att['content'], $att['name']);
                    }
                }
            }

            $mail->send();
            return ['success' => true, 'message' => 'Sent', 'debug_log' => $debugOutput];

        } catch (Exception $e) {
            // Close connection on error to allow a clean restart
            if (self::$mailerInstance) {
                self::$mailerInstance->smtpClose(); 
                self::$mailerInstance = null;
            }
            $debugOutput .= "\nMAILER ERROR: " . $e->getMessage();
            return ['success' => false, 'message' => $e->getMessage(), 'debug_log' => $debugOutput];
        }
    }
    
    // Call at the end of the script to close the connection
    public static function closeConnection() {
        if (self::$mailerInstance) {
            self::$mailerInstance->smtpClose();
        }
    }
}
?>
