#!/bin/bash
# UBI Drill v6 - Direct patch script
# Run as root on the CentOS/RHEL server
# Usage: sudo bash patch.sh

set -e
WEBROOT="/var/www/html"
DBDIR="/var/lib/ubibank"

echo "[*] Writing fixed PHP files..."

# ── 1. config/database.php ──────────────────────────────────────
cat > "$WEBROOT/config/database.php" << 'PHPEOF'
<?php
define('DB_PATH',    '/var/lib/ubibank/banking.db');
define('BACKUP_DIR', '/var/www/html/backup');
define('APP_VERSION','6.2.1');

// VULNERABLE: Hardcoded credentials (Scenario #8)
define('DB_PASS',          'UBI@SecureDB2024');
define('CBS_HOST',         'cbs.ubi.internal');
define('CBS_PASS',         'CBS@Prod#2024');
define('MYSQL_PASS',       'AuditDB@2024!');
define('SMTP_PASS',        'SMTP@Notify2024');
define('ADMIN_DEFAULT_PASS','AdminUBI@2024');
define('SESSION_SECRET',   'UBI_SESSION_K3Y_2024_STATIC');
define('JWT_SECRET',       'UBI_JWT_S3CR3T_NEVER_ROTATE');

function getDB() {
    static $db = null;
    if ($db === null) {
        $db = new PDO('sqlite:' . DB_PATH);
        $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $db->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
        $db->exec('PRAGMA foreign_keys = ON');
    }
    return $db;
}
PHPEOF
echo "[OK] config/database.php"

# ── 2. includes/auth.php ───────────────────────────────────────
cat > "$WEBROOT/includes/auth.php" << 'PHPEOF'
<?php
require_once '/var/www/html/config/database.php';

function session_init() {
    if (session_status() === PHP_SESSION_NONE) {
        // VULNERABLE: httponly=false (XSS Scenario #4)
        session_set_cookie_params(['lifetime'=>7200,'path'=>'/','httponly'=>false,'secure'=>false,'samesite'=>'Lax']);
        session_start();
    }
}

function is_logged_in() {
    session_init();
    return !empty($_SESSION['user_id']);
}

function check_auth($roles = null) {
    session_init();
    if (empty($_SESSION['user_id'])) {
        header('Location: /login.php');
        exit;
    }
    if ($roles !== null) {
        $allowed = is_array($roles) ? $roles : [$roles];
        if (!in_array($_SESSION['role'], $allowed)) {
            http_response_code(403);
            $page_title = 'Access Denied';
            include '/var/www/html/includes/header.php';
            echo '<div class="alert alert-danger" style="margin:20px"><h3>403 - Access Denied</h3><p>You do not have permission to view this page.</p><a href="/dashboard.php" class="btn btn-outline">Back to Dashboard</a></div>';
            include '/var/www/html/includes/footer.php';
            exit;
        }
    }
    return $_SESSION;
}

function login_user($username, $password) {
    $db   = getDB();
    $stmt = $db->prepare('SELECT id, username, password, full_name, role, email FROM users WHERE username = ? AND is_active = 1');
    $stmt->execute([trim($username)]);
    $user = $stmt->fetch();
    if ($user && password_verify($password, $user['password'])) {
        session_init();
        if (!headers_sent()) { session_regenerate_id(true); }
        $_SESSION['user_id']   = $user['id'];
        $_SESSION['username']  = $user['username'];
        $_SESSION['role']      = $user['role'];
        $_SESSION['full_name'] = $user['full_name'];
        $db->prepare('UPDATE users SET last_login = datetime("now") WHERE id = ?')->execute([$user['id']]);
        return $user;
    }
    return false;
}

function logout_user() {
    session_init();
    $_SESSION = [];
    session_destroy();
}

function get_api_token() {
    $h = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    if (preg_match('/Bearer\s+(.+)/i', $h, $m)) return trim($m[1]);
    return $_GET['token'] ?? null;
}

function check_api_auth() {
    header('Content-Type: application/json');
    $token = get_api_token();
    if (!$token) { http_response_code(401); die(json_encode(['status'=>'error','message'=>'Unauthorized'])); }
    $db   = getDB();
    $stmt = $db->prepare('SELECT s.user_id, u.username, u.role, u.full_name FROM sessions s JOIN users u ON s.user_id=u.id WHERE s.session_token=? AND s.expires_at>datetime("now") AND u.is_active=1');
    $stmt->execute([$token]);
    $sess = $stmt->fetch();
    if (!$sess) { http_response_code(401); die(json_encode(['status'=>'error','message'=>'Invalid or expired token'])); }
    return $sess;
}

function create_api_session($user_id) {
    $db    = getDB();
    $token = bin2hex(random_bytes(32));
    $exp   = date('Y-m-d H:i:s', strtotime('+2 hours'));
    $ip    = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    $db->prepare('DELETE FROM sessions WHERE user_id=? AND expires_at<datetime("now")')->execute([$user_id]);
    $db->prepare('INSERT INTO sessions (user_id,session_token,expires_at,ip_address) VALUES (?,?,?,?)')->execute([$user_id,$token,$exp,$ip]);
    return $token;
}
PHPEOF
echo "[OK] includes/auth.php"

# ── 3. index.php ───────────────────────────────────────────────
cat > "$WEBROOT/index.php" << 'PHPEOF'
<?php
require_once '/var/www/html/includes/auth.php';
session_init();
if (is_logged_in()) { header('Location: /dashboard.php'); } else { header('Location: /login.php'); }
exit;
PHPEOF
echo "[OK] index.php"

# ── 4. logout.php ──────────────────────────────────────────────
cat > "$WEBROOT/logout.php" << 'PHPEOF'
<?php
require_once '/var/www/html/includes/auth.php';
session_init();
logout_user();
header('Location: /login.php');
exit;
PHPEOF
echo "[OK] logout.php"

# ── 5. login.php ───────────────────────────────────────────────
# KEY FIX: Use PHP to build the entire page - no inline PHP in HTML body
cat > "$WEBROOT/login.php" << 'PHPEOF'
<?php
require_once '/var/www/html/includes/auth.php';
session_init();

if (is_logged_in()) {
    $dest = in_array($_SESSION['role'], ['admin','banker']) ? '/admin/index.php' : '/dashboard.php';
    header('Location: ' . $dest);
    exit;
}

$error = '';
$tab   = (isset($_GET['tab']) && $_GET['tab'] === 'register') ? 'register' : 'login';
$pre_u = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'login') {
    $u = trim($_POST['username'] ?? '');
    $p = $_POST['password'] ?? '';
    if ($u === '' || $p === '') {
        $error = 'Please enter both username and password.';
        $pre_u = htmlspecialchars($u, ENT_QUOTES);
    } else {
        $user = login_user($u, $p);
        if ($user) {
            $dest = in_array($user['role'], ['admin','banker']) ? '/admin/index.php' : '/dashboard.php';
            header('Location: ' . $dest);
            exit;
        } else {
            $error = 'Invalid username or password. Please try again.';
            $pre_u = htmlspecialchars($u, ENT_QUOTES);
        }
    }
}

// Build page fully in PHP - no inline PHP mixed in HTML
$tab_login_class    = $tab === 'login'    ? 'login-tab login-tab-active' : 'login-tab';
$tab_reg_class      = $tab === 'register' ? 'login-tab login-tab-active' : 'login-tab';
$error_html         = $error !== '' ? '<div class="alert alert-danger">&#9888; ' . htmlspecialchars($error, ENT_QUOTES) . '</div>' : '';

if ($tab === 'login') {
    $form_html = '
    <h3>Sign In</h3>
    <p class="sub">Enter your Internet Banking credentials</p>
    ' . $error_html . '
    <form method="POST" action="/login.php" autocomplete="off">
        <input type="hidden" name="action" value="login">
        <div class="form-group">
            <label for="fusername">Customer ID / Username</label>
            <input type="text" id="fusername" name="username" class="form-control"
                   placeholder="Enter your username" value="' . $pre_u . '" autocomplete="username">
        </div>
        <div class="form-group">
            <label for="fpassword">Internet Banking Password</label>
            <div class="input-wrap">
                <input type="password" id="fpassword" name="password" class="form-control"
                       placeholder="Enter your password" autocomplete="current-password">
                <button type="button" class="show-pw-btn" onclick="var f=document.getElementById(\'fpassword\');f.type=f.type===\'password\'?\'text\':\'password\'">&#128065;</button>
            </div>
        </div>
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;font-size:12.5px;">
            <label class="form-check"><input type="checkbox" name="remember"> Remember username</label>
            <a href="#" style="color:var(--primary);">Forgot Password?</a>
        </div>
        <button type="submit" class="btn-login">Login Securely</button>
    </form>
    <div style="margin-top:14px;padding:10px;background:#fff8e6;border-radius:8px;font-size:12px;color:#7a5500;border-left:3px solid #f0a000;">
        &#128737; UBI will never ask for your Password, PIN, or OTP via call, SMS, or email.
    </div>
    <div class="login-footer"><a href="/login.php?tab=register">New User? Register here</a></div>';
} else {
    $form_html = '
    <h3>New Registration</h3>
    <p class="sub">Create your Internet Banking account</p>
    <div id="reg-msg"></div>
    <form id="regForm">
        <div class="form-group">
            <label>Full Name</label>
            <input type="text" name="full_name" class="form-control" placeholder="As per bank records" required>
        </div>
        <div class="form-group">
            <label>Username</label>
            <input type="text" name="username" class="form-control" placeholder="Choose a username" required>
        </div>
        <div class="form-group">
            <label>Email</label>
            <input type="email" name="email" class="form-control" placeholder="Registered email" required>
        </div>
        <div class="form-group">
            <label>Password</label>
            <input type="password" name="password" class="form-control" placeholder="Min 8 characters" required>
        </div>
        <button type="submit" class="btn-login">Register Now</button>
    </form>
    <div class="login-footer"><a href="/login.php">Already registered? Sign In</a></div>
    <script>
    document.getElementById("regForm").addEventListener("submit",function(e){
        e.preventDefault();
        var d={};
        new FormData(this).forEach(function(v,k){d[k]=v;});
        var el=document.getElementById("reg-msg");
        el.innerHTML="<div class=\"alert alert-info\">Processing...</div>";
        fetch("/api/v1/register.php",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(d)})
        .then(function(r){return r.json();})
        .then(function(res){
            if(res.status==="success"){el.innerHTML="<div class=\"alert alert-success\">Registered! Redirecting...</div>";setTimeout(function(){window.location="/login.php";},1500);}
            else{el.innerHTML="<div class=\"alert alert-danger\">"+((res.message)||"Registration failed")+"</div>";}
        }).catch(function(){el.innerHTML="<div class=\"alert alert-danger\">Network error.</div>";});
    });
    </script>';
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Sign In - Union Bank of India</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Noto+Sans:wght@300;400;500;600;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="/assets/css/style.css">
</head>
<body class="login-page">
<div class="top-bar">
    <div>&#9742; Toll Free: <strong>1800-22-2244</strong> &nbsp;|&nbsp; <strong>1800-208-2244</strong></div>
    <div>Internet Banking Portal v6</div>
</div>
<div class="header">
    <div class="logo-section">
        <div class="logo-icon">UB</div>
        <div class="bank-name"><h1>Union Bank of India</h1><p>Good People to Bank With</p></div>
    </div>
    <div class="tricolor"><span></span><span></span><span></span></div>
</div>
<div class="notice-bar">
    <marquee scrollamount="3">&#9888; UBI will NEVER ask for your PIN, OTP, or Password over call, SMS, or email. &nbsp;|&nbsp; NEFT/RTGS available 24x7.</marquee>
</div>
<main class="main-content">
<div class="login-wrap">
    <div class="login-info">
        <h2>Welcome to<br>Internet Banking</h2>
        <p>Secure access to account management, fund transfers, and more - anytime, anywhere.</p>
        <ul>
            <li>Account Management &amp; Enquiry</li>
            <li>NEFT / RTGS / IMPS Fund Transfer</li>
            <li>Real-time Account Statements</li>
            <li>Bill Payments &amp; Recharges</li>
        </ul>
        <div class="security-note">&#128274; For authorized customers only. All activities are monitored.</div>
    </div>
    <div class="login-form">
        <div class="login-tabs">
            <a href="/login.php" class="<?php echo $tab_login_class; ?>">Sign In</a>
            <a href="/login.php?tab=register" class="<?php echo $tab_reg_class; ?>">New Registration</a>
        </div>
        <?php echo $form_html; ?>
    </div>
</div>
</main>
<footer class="footer">
    <div>&copy; 2024 Union Bank of India. All Rights Reserved.</div>
    <div class="badges"><span class="fbadge">RBI Regulated</span><span class="fbadge">DICGC Insured</span></div>
</footer>
</body>
</html>
PHPEOF
echo "[OK] login.php"

# ── 6. includes/header.php ────────────────────────────────────
cat > "$WEBROOT/includes/header.php" << 'PHPEOF'
<?php
// header.php - called AFTER check_auth() in each page
if (session_status() === PHP_SESSION_NONE) {
    session_set_cookie_params(['lifetime'=>7200,'path'=>'/','httponly'=>false,'secure'=>false,'samesite'=>'Lax']);
    session_start();
}
$_hi  = !empty($_SESSION['user_id']);
$_rol = $_SESSION['role'] ?? 'guest';
$_nm  = htmlspecialchars($_SESSION['full_name'] ?? 'Guest', ENT_QUOTES);
$_cur = basename($_SERVER['PHP_SELF'] ?? '');
$_dir = basename(dirname($_SERVER['PHP_SELF'] ?? ''));
$_aid = 0;
if ($_hi && $_rol === 'customer') {
    $__s = getDB()->prepare('SELECT id FROM accounts WHERE user_id=? AND is_active=1 LIMIT 1');
    $__s->execute([$_SESSION['user_id']]);
    $__r = $__s->fetch();
    $_aid = $__r ? (int)$__r['id'] : 0;
}
function _nav($f,$d=null){ global $_cur,$_dir; return ($_cur===$f&&($d===null||$_dir===$d))?' active':''; }
$_pt = htmlspecialchars($page_title ?? 'Union Bank of India', ENT_QUOTES);
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title><?php echo $_pt; ?></title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Noto+Sans:wght@300;400;500;600;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="/assets/css/style.css">
</head>
<body>
<div class="top-bar">
    <div>&#9742; Helpdesk: <strong>Ext. 4400</strong> &nbsp;|&nbsp; CBS v4.2.1</div>
    <div class="tb-right">
        <?php if ($_hi): ?>Logged in: <strong><?php echo $_nm; ?></strong> (<?php echo ucfirst($_rol); ?>) &nbsp;|&nbsp;<a href="/logout.php">Logout</a>
        <?php else: ?><a href="/login.php">Sign In</a><?php endif; ?>
    </div>
</div>
<div class="header">
    <div class="logo-section">
        <div class="logo-icon">UB</div>
        <div class="bank-name"><h1>Union Bank of India</h1><p><?php echo $_hi?'Internet Banking Portal':'Good People to Bank With'; ?></p></div>
    </div>
    <?php if ($_hi): ?><div class="header-right"><?php echo date('d M Y, h:i A'); ?> IST</div><?php endif; ?>
    <div class="tricolor"><span></span><span></span><span></span></div>
</div>
<?php if ($_hi): ?>
<div class="notice-bar"><marquee scrollamount="3">&#9888; UBI will NEVER ask for PIN/OTP via call/SMS/email. &nbsp;|&nbsp; NEFT/RTGS 24x7. &nbsp;|&nbsp; Always verify the URL.</marquee></div>
<div class="app-container">
<aside class="sidebar">
    <div class="sidebar-user">
        <div class="avatar"><?php echo strtoupper(substr($_nm,0,1)); ?></div>
        <div class="name"><?php echo $_nm; ?></div>
        <div class="role"><?php echo ucfirst($_rol); ?></div>
    </div>
    <nav class="sidebar-nav">
        <a href="/dashboard.php" class="nav-item<?php echo _nav('dashboard.php'); ?>"><span class="nav-icon">&#128202;</span> Dashboard</a>
        <?php if ($_aid): ?><a href="/account.php?id=<?php echo $_aid; ?>" class="nav-item<?php echo _nav('account.php'); ?>"><span class="nav-icon">&#127970;</span> My Account</a><?php endif; ?>
        <a href="/transfer.php" class="nav-item<?php echo _nav('transfer.php'); ?>"><span class="nav-icon">&#128184;</span> Fund Transfer</a>
        <a href="/support.php" class="nav-item<?php echo _nav('support.php'); ?>"><span class="nav-icon">&#9993;</span> Support</a>
        <a href="/profile.php" class="nav-item<?php echo _nav('profile.php'); ?>"><span class="nav-icon">&#128100;</span> Profile</a>
        <?php if (in_array($_rol,['admin','banker'])): ?>
        <div class="nav-divider"></div>
        <span class="nav-section">Administration</span>
        <a href="/admin/index.php" class="nav-item<?php echo _nav('index.php','admin'); ?>"><span class="nav-icon">&#128187;</span> Admin Panel</a>
        <a href="/admin/tickets.php" class="nav-item<?php echo _nav('tickets.php','admin'); ?>"><span class="nav-icon">&#127905;</span> Tickets</a>
        <a href="/admin/users.php" class="nav-item<?php echo _nav('users.php','admin'); ?>"><span class="nav-icon">&#128101;</span> Users</a>
        <?php endif; ?>
        <div class="nav-divider"></div>
        <a href="/logout.php" class="nav-item nav-item-danger"><span class="nav-icon">&#128682;</span> Logout</a>
    </nav>
</aside>
<main class="main-panel">
<?php else: ?><main>
<?php endif; ?>
PHPEOF
echo "[OK] includes/header.php"

# ── 7. includes/footer.php ───────────────────────────────────
cat > "$WEBROOT/includes/footer.php" << 'PHPEOF'
<?php $__li = !empty($_SESSION['user_id']); ?>
    </main>
<?php if ($__li): ?></div><?php endif; ?>
<footer class="footer">
    <div>&copy; 2024 Union Bank of India. All Rights Reserved. | Regulated by Reserve Bank of India</div>
    <div class="badges"><span class="fbadge">RBI Regulated</span><span class="fbadge">ISO 27001</span><span class="fbadge">PCI-DSS</span></div>
</footer>
<script src="/assets/js/app.js"></script>
</body>
</html>
PHPEOF
echo "[OK] includes/footer.php"

# ── 8. Fix session save path permissions ─────────────────────
mkdir -p /var/lib/php/sessions
chown apache:apache /var/lib/php/sessions 2>/dev/null || chown www-data:www-data /var/lib/php/sessions 2>/dev/null || true
chmod 700 /var/lib/php/sessions
echo "[OK] session path"

# ── 9. Fix PHP ini for session ───────────────────────────────
PHP_INI=$(php --ini 2>/dev/null | grep "Loaded Configuration" | awk '{print $NF}')
if [ -n "$PHP_INI" ] && [ -f "$PHP_INI" ]; then
    sed -i 's|^session.save_path.*|session.save_path = "/var/lib/php/sessions"|' "$PHP_INI"
    sed -i 's/^session\.cookie_httponly.*/session.cookie_httponly = 0/' "$PHP_INI"
    sed -i 's/^display_errors.*/display_errors = Off/' "$PHP_INI"
    echo "[OK] PHP ini tweaked ($PHP_INI)"
fi

# ── 10. Restart Apache ──────────────────────────────────────
apachectl configtest 2>&1 | grep -i "syntax\|error"
systemctl restart httpd 2>/dev/null && echo "[OK] Apache restarted" || echo "[WARN] Apache restart failed - check status"

# ── 11. Verify ──────────────────────────────────────────────
sleep 1
echo ""
echo "=== VERIFICATION ==="
HTTP=$(curl -s -o /dev/null -w "%{http_code}" http://localhost/login.php)
echo "login.php HTTP: $HTTP"

BODY=$(curl -s http://localhost/login.php)
PHP_LEAK=$(echo "$BODY" | grep -c "<?php\|<?=" || echo 0)
HAS_FORM=$(echo "$BODY" | grep -c "fusername\|Login Securely" || echo 0)
echo "PHP code visible: $PHP_LEAK (should be 0)"
echo "Login form present: $HAS_FORM (should be 1+)"

# Test actual login
LOGIN=$(curl -s -c /tmp/test_cook.txt -X POST http://localhost/login.php \
  -d "action=login&username=ankit.sharma&password=Ankit%40Pass1" \
  -w "\n%{http_code}\n%{redirect_url}")
CODE=$(echo "$LOGIN" | tail -2 | head -1)
REDIR=$(echo "$LOGIN" | tail -1)
echo "Login POST: HTTP $CODE → $REDIR"

echo ""
echo "=== PATCH COMPLETE ==="
echo "Test accounts:"
echo "  admin        / Admin@UBI2024   (admin)"
echo "  ankit.sharma / Ankit@Pass1     (customer)"
echo "  priya.mehta  / Priya@1234      (banker)"
