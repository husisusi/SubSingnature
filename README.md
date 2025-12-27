# 🖋️ SubSignature

**SubSignature** is a professional, self-hosted HTML email signature generator. It allows organizations to centrally manage, create, and export standardized email signatures using a powerful WYSIWYG editor.

![PHP](https://img.shields.io/badge/PHP-7.4%2B-777BB4?style=flat-square&logo=php&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-Database-003B57?style=flat-square&logo=sqlite&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

## ✨ Features

### 🎨 Design & Editing
- **Jodit Editor Integration:** A feature-rich WYSIWYG editor for creating complex HTML templates effortlessly.
- **Dynamic Placeholders:** Easily insert variables like `{name}`, `{role}`, `{phone}` into templates.
- **Live Preview:** See changes in real-time before saving.

### 💾 Data & Export
- **SQLite Database:** Zero-configuration, file-based storage. No MySQL server required.
- **CSV Export:** Export user data and signatures to `.csv` for external use (Excel, HR systems).
- **ZIP Download:** Download all generated signatures as individual HTML files in a single ZIP archive.

### 👥 User Management
- **Role-Based Access Control (RBAC):**
  - **Admin:** Full access to settings, user management, and global exports.
  - **User:** Access to personal profile and signature generation.
- **User Dashboard:** Clean interface for users to update their details.

### 🛡️ Enterprise-Grade Security
Built with security in mind based on modern standards:
- **Brute-Force Protection:** Account lockout after 5 failed login attempts.
- **Security Headers:** Implements `X-Frame-Options`, `X-XSS-Protection`, and `Strict-Transport-Security`.
- **Session Security:** Uses `HttpOnly` and `SameSite` cookies.
- **Audit Logging:** Detailed logs for security events and login attempts in `logs/`.

## 🚀 Installation

### Prerequisites
- PHP 7.4 or higher
- PHP Extensions: `sqlite3`, `mbstring`, `zip`, `json`
- Apache or Nginx Webserver

### Setup Guide

1. **Clone the Repository**
   ```bash
   git clone [https://github.com/husisuis/SubSignature.git](https://github.com/yourusername/SubSignature.git)
   cd SubSignature
