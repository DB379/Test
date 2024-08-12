<?php
global $db;
$userModel = new User($db);
$username = $_SESSION['username'];

// Fetch user's avatar
$avatar = $userModel->getAvatar($username);
$isDefaultAvatar = ($avatar === '../assets/img/users/default.png');

// Fetch user's theme preference (assuming 1 = light, 0 = dark)
$userTheme = $userModel->userTheme($username); // Assume userTheme() method is correctly implemented

// Determine the theme to apply
$theme = ($userTheme == 1) ? 'light' : 'dark';
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard</title>
    <link rel="stylesheet" href="assets/css/styles.css">
</head>

<body data-theme="<?php echo htmlspecialchars($theme); ?>">
    <div class="container">
        <nav class="sidebar">

            <div class="user-info">
                <?php if ($isDefaultAvatar) : ?>
                    <div class="default-avatar"></div>
                <?php else : ?>
                    <img src="assets/img/users/<?php echo htmlspecialchars($avatar); ?>" alt="User Avatar" class="user-avatar">
                <?php endif; ?>
                <h2>Welcome, <?php echo htmlspecialchars($username); ?></h2>
            </div>
            <ul>
                <?php
                foreach ($pages as $page => $data) {
                    if ($role >= $data['role']) {
                        $activeClass = ($currentPage == $page) ? 'active' : '';
                        echo "<li><a href=\"index.php?page=$page\" class=\"$activeClass\">{$data['title']}</a></li>";
                    }
                }
                ?>
            </ul>
            <div class="sidebar-buttons">
                <a href="index.php?page=settings" class="button <?php echo $currentPage == 'settings' ? 'active' : ''; ?>">Settings</a>
                <a href="index.php?page=logout" class="button logout">Logout</a>
            </div>
        </nav>
        <div class="content">
            <?php
            if (isset($contentPage)) {
                require $contentPage;
            } else {
                require 'public/dashboard.php';
            }
            ?>
        </div>
    </div>
</body>

</html>
