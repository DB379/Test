<?php
$csrf_token = $_SESSION['csrf_token'];

?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
    <link rel="stylesheet" href="../assets/css/global.css">
</head>

<body>
    <div class="login-container">
        <h2>Login</h2>
        <?php 
        if (isset($_SESSION['login_error'])) {
            echo '<p style="color:red;">' . htmlspecialchars($_SESSION['login_error']) . '</p>';
            unset($_SESSION['login_error']); // Clear the message after displaying
        }
        if (isset($_SESSION['success'])) {
            echo '<p style="color:green;">' . htmlspecialchars($_SESSION['success']) . '</p>';
            unset($_SESSION['success']); // Clear the message after displaying
        }
        ?>
        <form action="index.php?page=login" method="POST">
            <label for="username">Account Name</label>
            <input type="text" id="username" name="username" required>
            <label for="password">Password</label>
            <input type="password" id="password" name="password" required>
            <div class="remember-me">
                <input type="checkbox" id="remember" name="remember">
                <label for="remember">Remember me</label>
            </div>
            <button type="submit">Login</button>
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
        </form>
        <div class="register-link">
            <a href="index.php?page=register">Register new account.</a>
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
