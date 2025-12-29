<?php

require_once 'includes/config.php';

// Security Check: Only Admins allowed
requireAdmin();

// ---------------------------------------------------------
// 1. HANDLE POST REQUEST (Generate Download)
// ---------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    // CSRF Check (Security Prio 1)
    if (!isset($_POST['csrf_token']) || !verifyCSRFToken($_POST['csrf_token'])) {
        die("Security Error: Invalid CSRF Token.");
    }

    // Configuration
    ignore_user_abort(true);
    set_time_limit(300); 

    // Clear Buffers
    while (ob_get_level()) ob_end_clean();

    // Define Paths
    $base_dir = __DIR__; 
    $templates_dir = $base_dir . '/templates';

    if (!is_dir($templates_dir)) die("Error: Templates directory not found.");

    // Temp File
    $zip_path = tempnam(sys_get_temp_dir(), 'tpl_backup_');
    if ($zip_path === false) die("Error: Could not create temporary file.");

    $download_filename = 'subsignature_backup_' . date('Y-m-d_H-i-s') . '.zip';

    $zip = new ZipArchive();
    if ($zip->open($zip_path, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== TRUE) {
        unlink($zip_path); 
        die("Error: Could not open ZIP file.");
    }

    // Add Files Securely
    $template_files = glob($templates_dir . '/*.html');
    $count = 0;
    $real_templates_dir = realpath($templates_dir);

    if ($template_files) {
        foreach ($template_files as $file) {
            $real_file_path = realpath($file);
            // Security: Directory Traversal Check
            if ($real_file_path && is_file($real_file_path) && is_readable($real_file_path) && strpos($real_file_path, $real_templates_dir) === 0) {
                $zip->addFile($real_file_path, basename($real_file_path));
                $count++;
            }
        }
    }

    $zip->close();

    // Send Download
    if (file_exists($zip_path) && $count > 0) {
        header('Content-Type: application/zip');
        header('Content-Disposition: attachment; filename="' . $download_filename . '"');
        header('Content-Length: ' . filesize($zip_path));
        header('Pragma: public');
        header('Cache-Control: must-revalidate');
        
        readfile($zip_path);
        unlink($zip_path); // Cleanup
        exit;
    } else {
        if (file_exists($zip_path)) unlink($zip_path);
        die("Error: No templates found to backup.");
    }
}

// ---------------------------------------------------------
// 2. HANDLE GET REQUEST (Show UI)
// ---------------------------------------------------------

$csrf_token = generateCSRFToken();

// Count templates for display
$templates_dir = __DIR__ . '/templates';
$count = count(glob($templates_dir . '/*.html'));
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Backup - SubSignature</title>
    <link rel="stylesheet" href="css/style.css">
    <link rel="stylesheet" href="css/all.min.css">
    <style>
        /* Modern Backup Card Styling */
        .backup-hero {
            text-align: center;
            padding: 3rem 1rem;
            background: linear-gradient(to bottom, #f8fafc, #ffffff);
            border-bottom: 1px solid var(--border);
        }
        .backup-icon-circle {
            width: 80px; height: 80px;
            background: #e0e7ff; color: var(--primary);
            border-radius: 50%;
            display: flex; align-items: center; justify-content: center;
            font-size: 2.5rem; margin: 0 auto 1.5rem auto;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        }
        .stat-badge {
            background: #f1f5f9; color: var(--text-muted);
            padding: 4px 12px; border-radius: 20px;
            font-size: 0.85rem; font-weight: 600;
            display: inline-flex; align-items: center; gap: 6px;
            margin-bottom: 1.5rem;
        }

        /* Custom Modal Styling */
        .modal-overlay {
            position: fixed; top: 0; left: 0; width: 100%; height: 100%;
            background: rgba(0, 0, 0, 0.5);
            backdrop-filter: blur(4px);
            z-index: 1000;
            display: none; /* Hidden by default */
            align-items: center; justify-content: center;
            opacity: 0; transition: opacity 0.3s ease;
        }
        .modal-overlay.active { display: flex; opacity: 1; }
        
        .modal-box {
            background: white; width: 90%; max-width: 450px;
            border-radius: 12px; padding: 2rem;
            box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04);
            transform: translateY(20px); transition: transform 0.3s ease;
            text-align: center;
        }
        .modal-overlay.active .modal-box { transform: translateY(0); }
        
        .modal-icon {
            font-size: 3rem; color: var(--primary); margin-bottom: 1rem;
        }
        .modal-actions {
            display: grid; grid-template-columns: 1fr 1fr; gap: 1rem;
            margin-top: 2rem;
        }
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
                <span><?php echo isAdmin() ? 'Administrator' : 'User'; ?></span>
            </div>
        </div>
        <a href="logout.php" class="btn-logout"><i class="fas fa-sign-out-alt"></i> <span>Sign Out</span></a>
        <div style="text-align: center; margin-top: 0.75rem; font-size: 0.7rem; color: #94a3b8;">
            SubSignature <a href="about.php" style="color: inherit; text-decoration: none; font-weight: 600;">v1.0.1</a>
        </div>
    </div>
</aside>

<main class="main-content">
    <header class="page-header">
        <h2>Backup System</h2>
        <p>Manage and secure your template data.</p>
    </header>

    <div class="card" style="max-width: 700px; margin: 0 auto; overflow: hidden; padding: 0;">
        
        <div class="backup-hero">
            <div class="backup-icon-circle">
                <i class="fas fa-cube"></i>
            </div>
            <h3 style="font-size: 1.5rem; margin-bottom: 0.5rem;">Export Templates</h3>
            <p style="color: var(--text-muted); margin-bottom: 1.5rem;">
                Create a secure ZIP archive of all HTML signature templates.
            </p>
            
            <div class="stat-badge">
                <i class="fas fa-file-code"></i> <?php echo $count; ?> Templates found
            </div>
            
            <br>
            
            <button onclick="openModal()" class="btn btn-primary" style="padding: 0.8rem 2rem; font-size: 1rem;">
                <i class="fas fa-download"></i> Create Backup
            </button>
        </div>

        <div style="padding: 1.5rem; background: #fff; font-size: 0.9rem; color: var(--text-muted);">
            <strong><i class="fas fa-info-circle"></i> Note:</strong> 
            The backup includes all `.html` template files currently active in the system. 
            User data or database entries are not included in this specific archive.
        </div>
    </div>
</main>

<div class="modal-overlay" id="backupModal">
    <div class="modal-box">
        <div class="modal-icon"><i class="fas fa-file-zipper"></i></div>
        <h3 style="font-size: 1.4rem; margin-bottom: 0.5rem; color: var(--text-main);">Ready to download?</h3>
        <p style="color: var(--text-muted);">
            We are about to generate a ZIP file containing <strong><?php echo $count; ?> templates</strong>.
        </p>
        
        <form method="POST" action="backup_templates.php" id="downloadForm">
            <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
            
            <div class="modal-actions">
                <button type="button" class="btn btn-danger" onclick="closeModal()">
                    Cancel
                </button>
                <button type="submit" class="btn btn-primary" onclick="startDownload(this)">
                    <i class="fas fa-check"></i> Download
                </button>
            </div>
        </form>
    </div>
</div>

<script>
    const modal = document.getElementById('backupModal');

    function openModal() {
        modal.classList.add('active');
    }

    function closeModal() {
        modal.classList.remove('active');
    }

    // Close modal if clicking outside the box
    modal.addEventListener('click', function(e) {
        if (e.target === modal) closeModal();
    });

    // Handle Button Loading State
    function startDownload(btn) {
        btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Processing...';
        btn.style.opacity = '0.8';
        // Note: We don't disable the button because form submission might be blocked in some browsers if disabled immediately
        
        // Close modal after a short delay (UI feel)
        setTimeout(() => {
            closeModal();
            // Reset button
            setTimeout(() => {
                btn.innerHTML = '<i class="fas fa-check"></i> Download';
                btn.style.opacity = '1';
            }, 1000);
        }, 1500);
    }
</script>

</body>
</html>
