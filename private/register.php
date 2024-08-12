<?php
$csrf_token = $_SESSION['csrf_token'];
?>


<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register</title>
    <link rel="stylesheet" href="../assets/css/global.css">
</head>

<body>
    <div class="register-container">
        <h2>Register</h2>
        <?php 
        if (isset($_SESSION['register_error'])) {
            echo '<p style="color:red;">' . htmlspecialchars($_SESSION['register_error']) . '</p>';
            unset($_SESSION['register_error']); // Clear the message after displaying
        }
        if (isset($_SESSION['register_success'])) {
            echo '<p style="color:green;">' . htmlspecialchars($_SESSION['register_success']) . '</p>';
            unset($_SESSION['register_success']); // Clear the message after displaying
        }
        ?>
        <form action="index.php?page=register" method="POST">
            <label for="username">Account Name</label>
            <input type="text" id="username" name="username" required>
            <input type="email" id="email" name="email" required placeholder="Must use gmail, hotmail, outlook">
            <label for="password">Password</label>
            <input type="password" id="password" name="password" required>
            <label for="password_confirm">Confirm Password</label>
            <input type="password" id="password_confirm" name="password_confirm" required>
            <button type="submit">Register</button>
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
        </form>
        <div class="login-link">
            <a href="index.php?page=login">Login here</a>
        </div>
    </div>
</body>
</html>
<?php
/*
echo "Token generated: " . $_SESSION['csrf_token'] . "<br/>";
// Before displaying the form
echo "Token sent to form: " . $_SESSION['csrf_token'] . "<br/>";
// On form submission
echo "Token from session: " . $_SESSION['csrf_token'] . "<br/>";
*/
?>
