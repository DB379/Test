<?php


$userModel = new User($db);
$subpage = $subpage ?? 'profile';

require_once __DIR__ . '/../models/User.php';

if (!isset($_SESSION['username'])) {
    echo "<p>User is not logged in.</p>"; //
    return;
}

$username = $_SESSION['username'];

// Handle theme change request
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['theme'])) {
    $newTheme = $_POST['theme'] === 'light' ? 1 : 0; // 1 for light, 0 for dark
    $userModel->changeTheme($username, $newTheme);
    // Refresh the page to apply the new theme
    header("Location: ../index.php?page=settings/website");
    exit;
}

// Fetch user's current theme
$userTheme = $userModel->userTheme($username);
$theme = ($userTheme == 1) ? 'light' : 'dark';

try {
    $activities = $userModel->getRecentActivity($username);
} catch (Exception $e) {
    $error = $e->getMessage();
}
?>


</script>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Settings</title>
    <link rel="stylesheet" href="../assets/css/styles.css">
</head>
<style>

</style>


<body>
    <div class="container">
        <div class="content">
            <div class="settings-container">
                <nav class="tabs">
                    <a class="tab-button <?php echo $subpage === 'profile' ? 'active' : ''; ?>" href="index.php?page=settings/profile">Profile</a>
                    <a class="tab-button <?php echo $subpage === 'security' ? 'active' : ''; ?>" href="index.php?page=settings/security">Security</a>
                    <a class="tab-button <?php echo $subpage === 'website' ? 'active' : ''; ?>" href="index.php?page=settings/website">Website</a>
                    <a class="tab-button <?php echo $subpage === 'misc' ? 'active' : ''; ?>" href="index.php?page=settings/misc">Misc</a>
                </nav>


                <div id="profile" class="tab-content <?php echo $subpage === 'profile' ? 'active' : ''; ?>">
                    <h3>Avatars</h3>
                    <form class="avatars-form">
                         <div id="avatar-selection">
                                <?php
                                $avatars = ['avatar1.png', 'avatar2.png', 'avatar3.png', 'avatar4.png', 'avatar5.png', 'avatar6.png'];
                                foreach ($avatars as $avatar) {
                                    echo "<img src='../assets/img/users/{$avatar}' alt='{$avatar}' class='avatar' onclick='selectAvatar(\"{$avatar}\")' />";
                                }
                                ?>
                            </div>
                        <input type="hidden" id="selected-avatar" name="selected-avatar">
                        <button type="button" name="change_avatar" onclick="submitAvatar()">Change Avatar</button>
                    </form>

                    
                    <h3>Recent Activity</h3>
                    <div class="activity-table">
                        <?php if (isset($error)) : ?>
                            <p><?php echo htmlspecialchars($error); ?></p>
                        <?php else : ?>
                            <?php if (!empty($activities)) : ?>
                                <table>
                                    <tr>
                                        <th>Username</th>
                                        <th>Logged Time</th>
                                        <th>Logged Out</th>
                                    </tr>
                                    <?php foreach ($activities as $activity) : ?>
                                        <tr>
                                            <td><?= $userModel->formatActivity($activity['username']); ?></td>
                                            <td><?= $userModel->formatActivity($activity['logged_at']); ?></td>
                                            <td><?= $userModel->formatActivity($activity['logged_out']); ?></td>
                                        </tr>
                                    <?php endforeach; ?>
                                </table>
                            <?php else : ?>
                                <p>No recent activity found.</p>
                            <?php endif; ?>
                        <?php endif; ?>
                    </div>
                </div>
                <div id="security" class="tab-content <?php echo $subpage === 'security' ? 'active' : ''; ?>">
                    <h2>Security</h2>
                    <div class="form-group">
                        <h3>Change Password</h3>
                        <form method="POST" action="../index.php?page=changes">
                            <div>
                                <label for="old-password">Old Password</label>
                                <input type="password" id="old-password" name="old-password" required>
                            </div>
                            <div>
                                <label for="new-password">New Password</label>
                                <input type="password" id="new-password" name="new-password" required>
                            </div>
                            <div>
                                <label for="retype-password">Retype New Password</label>
                                <input type="password" id="retype-password" name="retype-password" required>
                            </div>
                            <button type="submit" name="change_password">Change Password</button>
                            <?php if (isset($_SESSION['password_error'])) : ?>
                                <div class="error"><?php echo htmlspecialchars($_SESSION['password_error']); ?></div>
                                <?php unset($_SESSION['password_error']); ?>
                            <?php endif; ?>
                            <?php if (isset($_SESSION['password_success'])) : ?>
                                <div class="success"><?php echo htmlspecialchars($_SESSION['password_success']); ?></div>
                                <?php unset($_SESSION['password_success']); ?>
                            <?php endif; ?>
                        </form>
                    </div>
                    <div class="form-group">
                        <h3>Change Email</h3>
                        <form method="POST" action="../index.php?page=changes">
                            <div><label for="old-email">Old Email</label>
                                <input type="email" id="old-email" name="old-email" required>
                            </div>
                            <div><label for="new-email">New Email</label>
                                <input type="email" id="new-email" name="new-email" required>
                            </div>
                            <div><label for="retype-email">Retype New Email</label>
                                <input type="email" id="retype-email" name="retype-email" required>
                            </div>
                            <button type="submit" name="change_email">Change Email</button>
                            <?php if (isset($_SESSION['email_error'])) : ?>
                                <div class="error"><?php echo htmlspecialchars($_SESSION['email_error']); ?></div>
                                <?php unset($_SESSION['email_error']); ?>
                            <?php endif; ?>
                            <?php if (isset($_SESSION['email_success'])) : ?>
                                <div class="success"><?php echo htmlspecialchars($_SESSION['email_success']); ?></div>
                                <?php unset($_SESSION['email_success']); ?>
                            <?php endif; ?>
                        </form>
                    </div>
                </div>

                <div id="website" class="tab-content <?php echo $subpage === 'website' ? 'active' : ''; ?>">
                    <!-- Website content here -->
                    <h3>Website Color Theme</h3>
                    <form id="theme-form" method="POST">
                        <input type="hidden" name="theme" id="theme-input">
                        <button type="button" name="dark" onclick="toggleTheme('dark')">Dark Theme</button>
                        <button type="button" name="light" onclick="toggleTheme('light')">Light Theme</button>
                    </form>
                </div>

                <div id="misc" class="tab-content <?php echo $subpage === 'misc' ? 'active' : ''; ?>">
                    <h2>Miscellaneous Settings</h2>
                    <div class="form-group">
                        <h3>Example Setting</h3>




                    </div>
                </div>
            </div>
        </div>
    </div>
    <script src="../assets/script/script.js"></script> <!-- Separate JS for settings -->
    <script src="../assets/script/avatars.js"></script>
    <script src="../assets/script/theme.js"></script>
</body>

</html>