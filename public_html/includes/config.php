<?php
// includes/config.php
// PRODUCTION READY - SECURITY PRIO 1

// ---------------------------------------------------------------------
// 1. PATH DEFINITIONS & DIRECTORY CHECKS
// ---------------------------------------------------------------------
define('BASE_DIR', __DIR__ . '/../../private_data');
define('DB_PATH', BASE_DIR . '/signatures.db');
define('LOG_DIR', BASE_DIR . '/logs');

// Ensure Log Directory exists
if (!file_exists(LOG_DIR)) {
    if (!mkdir(LOG_DIR, 0755, true)) {
        error_log("CRITICAL: Failed to create log directory at: " . LOG_DIR);
    }
}

// ---------------------------------------------------------------------
// 2. SECURE SESSION SETTINGS
// ---------------------------------------------------------------------
if (session_status() === PHP_SESSION_NONE) {
    session_start([
        'cookie_httponly' => true,
        'cookie_secure' => isset($_SERVER['HTTPS']), // Secure only if HTTPS is active
        'cookie_samesite' => 'Strict',
        'use_strict_mode' => true,
        'use_only_cookies' => true,
        'use_trans_sid' => false
    ]);
}

// Session Timeout (15 Minutes Idle)
$timeout_duration = 900; 
if (isset($_SESSION['last_activity'])) {
    if ((time() - $_SESSION['last_activity']) > $timeout_duration) {
        session_unset();
        session_destroy();
        header("Location: index.php?timeout=1");
        exit;
    }
}
$_SESSION['last_activity'] = time();

// ---------------------------------------------------------------------
// 3. SECURITY HEADERS
// ---------------------------------------------------------------------
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("X-XSS-Protection: 1; mode=block");
header("Referrer-Policy: strict-origin-when-cross-origin");
header("Permissions-Policy: geolocation=(), microphone=(), camera=()"); 

// ---------------------------------------------------------------------
// 4. DATABASE CONNECTION
// ---------------------------------------------------------------------
$db_folder = dirname(DB_PATH);

// Check Permissions
if (!is_dir($db_folder)) {
    if (!mkdir($db_folder, 0755, true)) {
        die("Setup Error: The private data directory is missing.");
    }
}
if (!is_writable($db_folder)) {
    die("CRITICAL ERROR: Web server needs WRITE access to: " . htmlspecialchars($db_folder));
}

try {
    $db = new SQLite3(DB_PATH);
    $db->busyTimeout(5000); 
    $db->exec('PRAGMA foreign_keys = ON');
    $db->exec('PRAGMA journal_mode = WAL;'); // Performance Mode
} catch (Exception $e) {
    error_log("Database Connection Error: " . $e->getMessage());
    die("System Error. Please check server logs.");
}

// ---------------------------------------------------------------------
// 5. DATABASE INITIALIZATION (SCHEMA)
// ---------------------------------------------------------------------
function initDatabase($db) {
    // 1. Users
    $db->exec("CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        email TEXT,
        full_name TEXT,
        role TEXT DEFAULT 'user',
        is_active BOOLEAN DEFAULT 1,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_login DATETIME,
        failed_login_attempts INTEGER DEFAULT 0,
        last_failed_login DATETIME,
        account_locked_until DATETIME
    )");
    
    // 2. Signatures
    $db->exec("CREATE TABLE IF NOT EXISTS user_signatures (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        role TEXT,
        email TEXT,
        phone TEXT,
        template TEXT DEFAULT 'signature_default.html',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )");
    
    // 3. Settings (User preferences)
    $db->exec("CREATE TABLE IF NOT EXISTS user_settings (
        user_id INTEGER PRIMARY KEY,
        default_template TEXT DEFAULT 'signature_default.html',
        theme TEXT DEFAULT 'light',
        items_per_page INTEGER DEFAULT 10,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )");
    
    // 4. System Config (SMTP, Defaults)
    $db->exec("CREATE TABLE IF NOT EXISTS system_settings (
        setting_key TEXT PRIMARY KEY, 
        setting_value TEXT
    )");
    // Default: New users inactive
    $db->exec("INSERT OR IGNORE INTO system_settings (setting_key, setting_value) VALUES ('default_user_active', '0')");
    
    // 5. Logging Tables
    $db->exec("CREATE TABLE IF NOT EXISTS login_attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address TEXT NOT NULL,
        username TEXT,
        attempted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        successful BOOLEAN DEFAULT 0,
        user_agent TEXT
    )");
    
    $db->exec("CREATE TABLE IF NOT EXISTS security_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_type TEXT NOT NULL,
        user_id INTEGER,
        ip_address TEXT NOT NULL,
        user_agent TEXT,
        details TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
    )");

    $db->exec("CREATE TABLE IF NOT EXISTS mail_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        signature_id INTEGER,
        recipient TEXT,
        status TEXT,
        message TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )");
}
initDatabase($db);

// ---------------------------------------------------------------------
// 6. INSTALLATION & SYSTEM CHECK
// ---------------------------------------------------------------------
$currentScript = basename($_SERVER['PHP_SELF']);
if ($currentScript !== 'install.php') {
    // Check for Users Table
    $tablesExist = $db->querySingle("SELECT name FROM sqlite_master WHERE type='table' AND name='users'");
    if (!$tablesExist) { header('Location: install.php'); exit; }
    
    // Check for Admin Account
    $adminCount = $db->querySingle("SELECT COUNT(*) FROM users WHERE role = 'admin'");
    if ($adminCount == 0) { header('Location: install.php'); exit; }
}

// ---------------------------------------------------------------------
// 7. AUTH & ACCESS CONTROL HELPERS
// ---------------------------------------------------------------------

function isAdmin() {
    return isset($_SESSION['role']) && $_SESSION['role'] === 'admin';
}

function isLoggedIn() {
    return isset($_SESSION['loggedin']) && $_SESSION['loggedin'] === true;
}

function requireLogin() {
    if (!isLoggedIn()) {
        header('Location: index.php');
        exit;
    }
    // Security Prio 1: Check if account is still active immediately
    global $db;
    $stmt = $db->prepare("SELECT is_active FROM users WHERE id = ?");
    $stmt->bindValue(1, $_SESSION['user_id'], SQLITE3_INTEGER);
    $result = $stmt->execute();
    
    if ($user = $result->fetchArray(SQLITE3_ASSOC)) {
        if ($user['is_active'] == 0) {
            session_destroy();
            header('Location: index.php?error=Account+deactivated');
            exit;
        }
    }
}

function requireAdmin() {
    requireLogin();
    if (!isAdmin()) {
        header('Location: generator.php');
        exit;
    }
}

// CSRF Helpers
function generateCSRFToken() {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function verifyCSRFToken($token) {
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

// ---------------------------------------------------------------------
// 8. SECURITY & LOGGING FUNCTIONS
// ---------------------------------------------------------------------

// Rate Limiting (Prevent Brute Force)
function checkRateLimit($action, $limit = 5, $timeframe = 300) {
    if (!isset($_SESSION['rate_limits'])) $_SESSION['rate_limits'] = [];
    
    $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    $key = "{$action}_{$ip}";
    $current_time = time();
    
    if (!isset($_SESSION['rate_limits'][$key])) {
        $_SESSION['rate_limits'][$key] = ['count' => 1, 'first' => $current_time];
        return true;
    }
    
    // Reset if timeframe expired
    if ($current_time - $_SESSION['rate_limits'][$key]['first'] > $timeframe) {
        $_SESSION['rate_limits'][$key] = ['count' => 1, 'first' => $current_time];
        return true;
    }
    
    // Check limit
    if ($_SESSION['rate_limits'][$key]['count'] >= $limit) {
        global $db;
        logSecurityEventToDB($db, 'RATE_LIMIT_EXCEEDED', null, "Action: $action, IP: $ip");
        return false;
    }
    
    $_SESSION['rate_limits'][$key]['count']++;
    return true;
}

// Database Logging
function logSecurityEventToDB($db, $event_type, $user_id = null, $details = '') {
    $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    $ua = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
    try {
        $stmt = $db->prepare("INSERT INTO security_events (event_type, user_id, ip_address, user_agent, details) VALUES (?, ?, ?, ?, ?)");
        $stmt->bindValue(1, $event_type, SQLITE3_TEXT);
        $stmt->bindValue(2, $user_id, SQLITE3_INTEGER);
        $stmt->bindValue(3, $ip, SQLITE3_TEXT);
        $stmt->bindValue(4, $ua, SQLITE3_TEXT);
        $stmt->bindValue(5, $details, SQLITE3_TEXT);
        $stmt->execute();
    } catch (Exception $e) {
        // Silent fail or file log
        error_log("DB Log Error: " . $e->getMessage());
    }
}

// Login Logic (Attempts, Locking)
function logLoginAttempt($db, $username, $successful, $ip = null, $user_agent = null) {
    $ip = $ip ?? ($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0');
    $ua = $user_agent ?? ($_SERVER['HTTP_USER_AGENT'] ?? 'Unknown');
    
    $stmt = $db->prepare("INSERT INTO login_attempts (ip_address, username, successful, user_agent) VALUES (?, ?, ?, ?)");
    $stmt->bindValue(1, $ip, SQLITE3_TEXT);
    $stmt->bindValue(2, $username, SQLITE3_TEXT);
    $stmt->bindValue(3, $successful ? 1 : 0, SQLITE3_INTEGER);
    $stmt->bindValue(4, $ua, SQLITE3_TEXT);
    $stmt->execute();
    
    if (!$successful && !empty($username)) {
        $stmt = $db->prepare("UPDATE users SET failed_login_attempts = failed_login_attempts + 1, last_failed_login = datetime('now') WHERE username = ?");
        $stmt->bindValue(1, $username, SQLITE3_TEXT);
        $stmt->execute();
        logSecurityEventToDB($db, 'LOGIN_FAILED', null, "User: $username");
    }
    
    if ($successful && !empty($username)) {
        $stmt = $db->prepare("UPDATE users SET failed_login_attempts = 0, last_login = datetime('now'), account_locked_until = NULL WHERE username = ?");
        $stmt->bindValue(1, $username, SQLITE3_TEXT);
        $stmt->execute();
        
        $uID = $db->querySingle("SELECT id FROM users WHERE username = '" . $db->escapeString($username) . "'");
        if($uID) logSecurityEventToDB($db, 'LOGIN_SUCCESS', $uID, "User: $username");
    }
}

function isAccountLocked($db, $username) {
    $stmt = $db->prepare("SELECT failed_login_attempts, account_locked_until FROM users WHERE username = ?");
    $stmt->bindValue(1, $username, SQLITE3_TEXT);
    $res = $stmt->execute();
    
    if ($user = $res->fetchArray(SQLITE3_ASSOC)) {
        if ($user['failed_login_attempts'] >= 5) {
            if (!empty($user['account_locked_until'])) {
                // Check if lock expired
                if (time() < strtotime($user['account_locked_until'])) return true; 
                // Unlock
                $db->exec("UPDATE users SET failed_login_attempts = 0, account_locked_until = NULL WHERE username = '" . $db->escapeString($username) . "'");
                return false;
            } else {
                // Set Lock (15 Min)
                $lock = date('Y-m-d H:i:s', time() + 900);
                $stmt = $db->prepare("UPDATE users SET account_locked_until = ? WHERE username = ?");
                $stmt->bindValue(1, $lock, SQLITE3_TEXT);
                $stmt->bindValue(2, $username, SQLITE3_TEXT);
                $stmt->execute();
                logSecurityEventToDB($db, 'ACCOUNT_LOCKED', null, "User: $username");
                return true;
            }
        }
    }
    return false;
}

// ---------------------------------------------------------------------
// 9. UTILITIES & ERROR HANDLING
// ---------------------------------------------------------------------

function validatePasswordPolicy($password) {
    $errors = [];
    if (strlen($password) < 8) $errors[] = "Password must be at least 8 characters";
    if (!preg_match('/[A-Z]/', $password)) $errors[] = "At least one uppercase letter";
    if (!preg_match('/[a-z]/', $password)) $errors[] = "At least one lowercase letter";
    if (!preg_match('/[0-9]/', $password)) $errors[] = "At least one number";
    return $errors;
}

function sanitizeInput($input) {
    if (is_array($input)) return array_map('sanitizeInput', $input);
    return htmlspecialchars(trim($input), ENT_QUOTES, 'UTF-8');
}

// Disable Display Errors for Production
ini_set('display_errors', 0);
ini_set('log_errors', 1);
ini_set('error_log', LOG_DIR . '/php_errors.log');

// Class Autoloader
spl_autoload_register(function ($class_name) {
    $file = __DIR__ . '/../classes/' . $class_name . '.php';
    if (file_exists($file)) require_once $file;
});
?>
