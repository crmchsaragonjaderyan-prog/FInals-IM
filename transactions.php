
<?php
session_start();

if (empty($_SESSION['user_id'])) {
    header('Location: index.php?page=login');
    exit;
}

header('Location: index.php?page=transactions');
exit;
