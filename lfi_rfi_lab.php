<?php
// Simple LFI/RFI Vulnerable Script

if (isset($_GET['file'])) {
    $file = $_GET['file'];

    // Prevent null-byte injection
    $file = str_replace("\0", "", $file);

    // Display the requested file
    include($file);
} else {
    echo "Use ?file=filename.php to include a file.";
}
?>
