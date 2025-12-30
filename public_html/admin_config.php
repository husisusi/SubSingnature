<?php

require_once 'includes/config.php';
requireAdmin(); // Security Prio 1: Only Admins

// 1. AUTO-SETUP: Ensure Settings Table Exists
// This ensures the script works immediately without manual SQL execution.
$db->exec("CREATE TABLE IF NOT EXISTS system_settings (
    setting_key TEXT PRIMARY KEY, 
    setting_value TEXT
)");

// 2. Initialize Variables
$message = '';
$error = '';

// Helper function to get setting with default fallback
function getSetting($db, $key, $default) {
    $stmt = $db->prepare("SELECT setting_value FROM system_settings WHERE setting_key = ?");
    $stmt->bindValue(1, $key, SQLITE3_TEXT);
    $result = $stmt->execute();
    $row = $result->fetchArray(SQLITE3_ASSOC);
    return ($row) ? $row['setting_value'] : $default;
}

// 3. Handle Form Submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    
    // Security: CSRF Check
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        die("Security Error: Invalid CSRF Token.");
    }

    // Process: Default User Status
    $default_status = isset($_POST['default_user_active']) ? (int)$_POST['default_user_active'] : 1;
    
    // Upsert (Insert or Replace) into SQLite
    $stmt = $db->prepare("INSERT OR REPLACE INTO system_settings (setting_key, setting_value) VALUES ('default_user_active', ?)");
    $stmt->bindValue(1, $default_status, SQLITE3_TEXT);
    
    if ($stmt->execute()) {
        $message = "System configuration updated successfully.";
    } else {
        $error = "Failed to update configuration.";
    }
}

// 4. Fetch Current Settings for Display
$current_default_active = (int)getSetting($db, 'default_user_active', '1'); // Default to 1 (Active) if not set

// Security: Generate CSRF Token
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>System Configuration - SubSignature</title>
    <link rel="stylesheet" href="css/style.css">
    <link rel="stylesheet" href="css/all.min.css">
    <style>
        .config-card {
            background: white;
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 2rem;
            max-width: 600px;
        }
        .config-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 1rem 0;
            border-bottom: 1px solid var(--border);
        }
        .config-item:last-child { border-bottom: none; }
        .config-label h4 { margin: 0 0 0.25rem 0; color: var(--text-main); }
        .config-label p { margin: 0; color: var(--text-muted); font-size: 0.85rem; }
        
        /* Modern Switch Toggle */
        .switch { position: relative; display: inline-block; width: 50px; height: 26px; }
        .switch input { opacity: 0; width: 0; height: 0; }
        .slider {
            position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0;
            background-color: #cbd5e1; -webkit-transition: .4s; transition: .4s; border-radius: 34px;
        }
        .slider:before {
            position: absolute; content: ""; height: 20px; width: 20px; left: 3px; bottom: 3px;
            background-color: white; -webkit-transition: .4s; transition: .4s; border-radius: 50%;
        }
        input:checked + .slider { background-color: var(--primary); }
        input:focus + .slider { box-shadow: 0 0 1px var(--primary); }
        input:checked + .slider:before { -webkit-transform: translateX(24px); -ms-transform: translateX(24px); transform: translateX(24px); }
    </style>
</head>
<body>

    <aside class="sidebar">
        <?php include 'includes/navbar.php'; ?>
        <div class="sidebar-footer">
            <div class="user-profile">
                <div class="avatar"><?php echo strtoupper(substr($_SESSION['username'], 0, 1)); ?></div>
                <div class="user-info">
                    <div><?php echo htmlspecialchars($_SESSION['username']); ?></div>
                    <span>Administrator</span>
                </div>
            </div>
            <a href="logout.php" class="btn-logout"><i class="fas fa-sign-out-alt"></i> <span>Sign Out</span></a>
        </div>
    </aside>

    <main class="main-content">
        <header class="page-header">
            <h2>System Configuration</h2>
            <p>Manage global application settings and defaults.</p>
        </header>

        <?php if ($message): ?>
            <div class="alert alert-success"><i class="fas fa-check-circle"></i> <?php echo htmlspecialchars($message); ?></div>
        <?php endif; ?>
        <?php if ($error): ?>
            <div class="alert alert-error"><i class="fas fa-exclamation-circle"></i> <?php echo htmlspecialchars($error); ?></div>
        <?php endif; ?>

        <form method="POST" action="admin_config.php">
            <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
            
            <section class="config-card">
                <div style="margin-bottom: 1.5rem; border-bottom: 1px solid var(--border); padding-bottom: 1rem;">
                    <h3 style="font-size: 1.2rem;"><i class="fas fa-users-cog"></i> User Registration Defaults</h3>
                </div>

                <div class="config-item">
                    <div class="config-label">
                        <h4>Default Account Status is Active</h4>
                        <p>When an User creates a new user, should they be active immediately?</p>
                    </div>
                    <div>
                        <label class="switch">
                            <input type="hidden" name="default_user_active" value="0">
                            <input type="checkbox" name="default_user_active" value="1" <?php echo ($current_default_active == 1) ? 'checked' : ''; ?>>
                            <span class="slider"></span>
                        </label>
                    </div>
                </div>

                <div class="form-actions" style="margin-top: 2rem; display: flex; justify-content: flex-end;">
                    <button type="submit" class="btn btn-primary">
                        <i class="fas fa-save"></i> Save Changes
                    </button>
                </div>
            </section>
        </form>

    </main>
</body>
</html>
