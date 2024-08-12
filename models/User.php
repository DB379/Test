<?php


class User
{
    private $db;

    public function __construct($db)
    {
        $this->db = $db;
    }

    public function fetchTable()
    {

        $sql = "SELECT id, username, email, joindate FROM accounts"; // Adjust columns as needed
        try {
            $stmt = $this->db->prepare($sql);
            $stmt->execute();
            return $stmt->fetchAll(PDO::FETCH_ASSOC);
        } catch (PDOException $e) {
            die("Error fetching users: " . $e->getMessage());
        }
    }



    // Function to get the user's theme
    public function userTheme($username)
    {

        $sql = "SELECT theme FROM accounts WHERE username = :username";
        try {
            $stmt = $this->db->prepare($sql);
            $stmt->bindParam(':username', $username, PDO::PARAM_STR);
            $stmt->execute();
            $result = $stmt->fetch(PDO::FETCH_ASSOC);
            return $result ? $result['theme'] : null;
        } catch (PDOException $e) {
            die("Error fetching user theme: " . $e->getMessage());
        }
    }




    // Function to update the user's theme
    public function changeTheme($username, $theme)
    {


        $sql = "UPDATE accounts SET theme = :theme WHERE username = :username";
        try {
            $stmt = $this->db->prepare($sql);
            $stmt->bindParam(':theme', $theme, PDO::PARAM_INT);
            $stmt->bindParam(':username', $username, PDO::PARAM_STR);
            $stmt->execute();
        } catch (PDOException $e) {
            die("Error updating theme: " . $e->getMessage());
        }
    }


    // Authentication
    public function authenticate($username, $password)
    {
        $this->checkRateLimit();

        $stmt = $this->db->prepare("SELECT * FROM accounts WHERE username = :username");
        $stmt->bindParam(':username', $username);
        $stmt->execute();
        $user = $stmt->fetch();

        if ($user && password_verify($password, $user['verifier'])) {
            $this->clearLoginAttempts();
            return $user;
        } else {
            $this->incrementFailedLogin($username);
        }
        return false;
    }

    // Rate limiting
    public function checkRateLimit()
    {

        $ip_address = $_SERVER['REMOTE_ADDR'];
        $stmt = $this->db->prepare("SELECT * FROM login_attempts WHERE ip_address = :ip_address");
        $stmt->bindParam(':ip_address', $ip_address);
        $stmt->execute();
        $attempt = $stmt->fetch();

        if ($attempt) {
            $lockoutTime = 3600; // 1 hour in seconds
            $elapsedTime = time() - strtotime($attempt['attempt_time']); // Calculate elapsed time on server side

            if ($attempt['failed_attempts'] >= 10 && $elapsedTime < $lockoutTime) {
                throw new Exception("Your IP is locked due to multiple failed login attempts. Please try again later.");
            } elseif ($elapsedTime >= $lockoutTime) {
                $stmt = $this->db->prepare("DELETE FROM login_attempts WHERE ip_address = :ip_address");
                $stmt->bindParam(':ip_address', $ip_address);
                $stmt->execute();
            }
        }
    }
    // Function to increment failed login attempts
    public function incrementFailedLogin($username)
    {

        $ip_address = $_SERVER['REMOTE_ADDR'];
        $stmt = $this->db->prepare("SELECT * FROM login_attempts WHERE ip_address = :ip_address");
        $stmt->bindParam(':ip_address', $ip_address);
        $stmt->execute();
        $attempt = $stmt->fetch();

        if ($attempt) {
            $failed_attempts = $attempt['failed_attempts'] + 1;
            $stmt = $this->db->prepare("UPDATE login_attempts SET failed_attempts = :failed_attempts, attempt_time = NOW() WHERE ip_address = :ip_address");
            $stmt->bindParam(':failed_attempts', $failed_attempts);
            $stmt->bindParam(':ip_address', $ip_address);
            $stmt->execute();
        } else {
            $failed_attempts = 1;
            $stmt = $this->db->prepare("INSERT INTO login_attempts (ip_address, failed_attempts, attempt_time) VALUES (:ip_address, 1, NOW())");
            $stmt->bindParam(':ip_address', $ip_address);
            $stmt->execute();
        }

        $stmt = $this->db->prepare("UPDATE accounts SET failed_login = failed_login + 1 WHERE username = :username");
        $stmt->bindParam(':username', $username);
        $stmt->execute();

        if ($failed_attempts == 5) {
            throw new Exception("Warning: 5 failed login attempts. Your IP will be locked after 10 attempts.");
        } elseif ($failed_attempts >= 10) {
            throw new Exception("Your IP is locked due to multiple failed login attempts. Please try again later.");
        }
    }
    // Function to clear login attempts
    public function clearLoginAttempts()
    {

        $ip_address = $_SERVER['REMOTE_ADDR'];
        $stmt = $this->db->prepare("DELETE FROM login_attempts WHERE ip_address = :ip_address");
        $stmt->bindParam(':ip_address', $ip_address);
        $stmt->execute();
    }

    // Function to check if the user is logged in
    public function isLoggedIn()
    {
        if (isset($_SESSION['username']) && isset($_SESSION['session_key'])) {
            return true;
        } elseif (isset($_COOKIE['username']) && isset($_COOKIE['session_key'])) {
            $username = $_COOKIE['username'];
            $session_key = $_COOKIE['session_key'];
            $user = $this->verifySessionKey($username, $session_key);
            if ($user) {
                $_SESSION['username'] = $username;
                $_SESSION['session_key'] = $session_key;
                $_SESSION['last_activity'] = time();
                return true;
            }
        }
        return false;
    }

    // Function to verify the session key
    public function verifySessionKey($username, $session_key)
    {

        $stmt = $this->db->prepare("SELECT * FROM accounts WHERE username = :username AND session_key = :session_key");
        $stmt->bindParam(':username', $username, PDO::PARAM_STR);
        $stmt->bindParam(':session_key', $session_key, PDO::PARAM_STR);
        $stmt->execute();
        return $stmt->fetch(PDO::FETCH_ASSOC);
    }

    // Function to generate a session key
    public function generateSessionKey($username)
    {

        $session_key = bin2hex(random_bytes(32));
        $stmt = $this->db->prepare("UPDATE accounts SET session_key = :session_key, last_ip = :last_ip, failed_login = 0 WHERE username = :username");
        $stmt->bindParam(':session_key', $session_key);
        $stmt->bindParam(':last_ip', $_SERVER['REMOTE_ADDR']);
        $stmt->bindParam(':username', $username);
        $stmt->execute();

        $this->logLogin($username);

        return $session_key;
    }

    // Function to log the user's login
    private function logLogin($username)
    {

        $stmt = $this->db->prepare("INSERT INTO login_status (username, logged_at) VALUES (:username, NOW())");
        $stmt->bindParam(':username', $username);
        $stmt->execute();
    }

    // Function to get the user's level
    public function setLoggedStatus($username, $status)
    {

        $stmt = $this->db->prepare("UPDATE accounts SET logged = :status WHERE username = :username");
        $stmt->bindParam(':username', $username);
        $stmt->bindParam(':status', $status);
        $stmt->execute();
    }

    // Function to check if the user is logged in
    public function checkUserLevel($username)
    {

        $stmt = $this->db->prepare("SELECT level FROM accounts WHERE username = :username");
        $stmt->bindParam(':username', $username, PDO::PARAM_STR);
        $stmt->execute();
        $result = $stmt->fetch(PDO::FETCH_ASSOC);
        return $result ? $result['level'] : null;
    }

    // Check user status
    public function checkUserStatus($username)
    {

        $stmt = $this->db->prepare("SELECT status FROM accounts WHERE username = :username");
        $stmt->bindParam(':username', $username, PDO::PARAM_STR);
        $stmt->execute();
        $result = $stmt->fetch(PDO::FETCH_ASSOC);
        return $result ? $result['status'] : null;
    }

    // Checks if username is already taken in the database
    public function isUsernameTaken($username)
    {

        $stmt = $this->db->prepare("SELECT COUNT(*) FROM accounts WHERE username = :username");
        $stmt->bindParam(':username', $username);
        $stmt->execute();
        $count = $stmt->fetchColumn();
        return $count > 0;
    }

    // Checks if email is already taken in the database
    public function isEmailTaken($email)
    {

        $stmt = $this->db->prepare("SELECT COUNT(*) FROM accounts WHERE email = :email");
        $stmt->bindParam(':email', $email);
        $stmt->execute();
        $count = $stmt->fetchColumn();
        return $count > 0;
    }

    public function register($username, $email, $password)
    {

        // Validate input
        if (!$this->validateUsername($username) || !$this->validateEmail($email) || !$this->validatePassword($password)) {
            throw new InvalidArgumentException("Validation failed for username, email, or password.");
        }

        // Check for existing username or email
        if ($this->isUsernameTaken($username)) {
            throw new InvalidArgumentException("Username already in use.");
        }
        if ($this->isEmailTaken($email)) {
            throw new InvalidArgumentException("Email already in use.");
        }

        // Hash the password
        $verifier = password_hash($password, PASSWORD_ARGON2ID);

        // Prepare the SQL statement
        $stmt = $this->db->prepare("INSERT INTO accounts (username, verifier, email, last_ip) VALUES (:username, :verifier, :email, :last_ip)");
        $stmt->bindParam(':username', $username);
        $stmt->bindParam(':verifier', $verifier);
        $stmt->bindParam(':email', $email);
        $stmt->bindParam(':last_ip', $_SERVER['REMOTE_ADDR']);

        // Execute the statement
        if (!$stmt->execute()) {
            throw new Exception("Registration failed.");
        }
        return true;
    }
    // CSRF token regeneration
    public function regenerateCSRFToken()
    {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        return $_SESSION['csrf_token'];
    }

    // CSRF protection
    public function generateCsrfToken()
    {
        if (empty($_SESSION['csrf_token'])) {
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        }
        return $_SESSION['csrf_token'];
    }

    // CSRF validation
    public function validateCsrfToken($token)
    {
        return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
    }

    // Function to sanitize input
    public function sanitizeInput($data, $encoding = 'UTF-8')
    {
        $data = trim($data); // Remove whitespace from the beginning and end.
        $data = stripslashes($data); // Remove backslashes (useful if magic quotes are still enabled).
        $data = htmlspecialchars($data, ENT_QUOTES | ENT_HTML5, $encoding); // Convert special characters to HTML entities.
        return $data;
    }


    // Function to change the user's password
    public function changePassword($username, $oldPassword, $newPassword)
    {

        try {
            $this->db->beginTransaction();
            if ($oldPassword === $newPassword) {
                return false;
            }

            $stmt = $this->db->prepare("SELECT * FROM accounts WHERE username = :username");
            $stmt->bindParam(':username', $username);
            $stmt->execute();
            $user = $stmt->fetch(PDO::FETCH_ASSOC);

            if (!$user || !password_verify($oldPassword, $user['verifier'])) {
                return false;
            }

            if (!$this->validatePassword($newPassword)) {
                return false;
            }

            $newPasswordHash = password_hash($newPassword, PASSWORD_ARGON2ID);
            $stmt = $this->db->prepare("UPDATE accounts SET verifier = :verifier WHERE username = :username");
            $stmt->bindParam(':verifier', $newPasswordHash);
            $stmt->bindParam(':username', $username);
            $stmt->execute();
            $this->db->commit();
            return true;
        } catch (Exception $e) {
            $this->db->rollBack();
            return false;
        }
    }

    public function changeEmail($username, $oldEmail, $newEmail)
    {

        try {
            $this->db->beginTransaction();
            if ($oldEmail === $newEmail) {
                return false;
            }
            if (!$this->validateEmail($newEmail)) {
                return false;
            }

            $stmt = $this->db->prepare("SELECT * FROM accounts WHERE username = :username AND email = :email");
            $stmt->bindParam(':username', $username);
            $stmt->bindParam(':email', $oldEmail);
            $stmt->execute();
            $user = $stmt->fetch(PDO::FETCH_ASSOC);

            if (!$user) {
                return false;
            }

            $stmt = $this->db->prepare("UPDATE accounts SET email = :email WHERE username = :username");
            $stmt->bindParam(':email', $newEmail);
            $stmt->bindParam(':username', $username);
            $stmt->execute();
            $this->db->commit();
            return true;
        } catch (Exception $e) {
            $this->db->ollBack();
            return false;
        }
    }
    // Function to get the user's recent activity
    public function getRecentActivity($username)
    {

        try {
            // Prepare and execute the query to fetch user activities
            $stmt = $this->db->prepare("SELECT username, logged_at, logged_out FROM login_status WHERE username = :username ORDER BY logged_at DESC LIMIT 10");
            $stmt->execute(['username' => $username]);

            // Fetch all records
            return $stmt->fetchAll(PDO::FETCH_ASSOC);
        } catch (PDOException $e) {
            throw new Exception("Error fetching activity: " . htmlspecialchars($e->getMessage()));
        }
    }
    // Function to format the activity
    public function formatActivity($value)
    {
        return $value ? htmlspecialchars($value) : '-';
    }


    public function validateUsername($username)
    {
        return preg_match('/^[a-zA-Z0-9]{4,20}$/', $username);
    }

    // Function to validate the password
    function validatePassword($password)
    {
        // Check if the length of the password is between 6 and 20 characters
        $lengthValid = strlen($password) >= 5 && strlen($password) <= 20;

        // Check if the password contains only letters (case-sensitive)
        $onlyLetters = preg_match('/^[a-zA-Z]+$/', $password);

        // Check if the password contains only numbers
        $onlyNumbers = preg_match('/^[0-9]+$/', $password);

        // Check if the password contains a mix of letters and numbers
        $containsLettersAndNumbers = preg_match('/[a-zA-Z]/', $password) && preg_match('/[0-9]/', $password);

        // Return true if length is valid and any of the conditions are met
        return $lengthValid && ($onlyLetters || $onlyNumbers || $containsLettersAndNumbers);
    }

    // Function to validate the email
    public function validateEmail($email)
    {
        return filter_var($email, FILTER_VALIDATE_EMAIL);
    }

    public function updateAvatar($username, $avatarFilename)
    {

        $sql = "UPDATE accounts SET profile_pic = :avatar WHERE username = :username";
        $stmt = $this->db->prepare($sql);
        $stmt->bindParam(':avatar', $avatarFilename);
        $stmt->bindParam(':username', $username);
        return $stmt->execute();
    }

    

    // Function to get the user's avatar or return a default
    public function getAvatar($username)
    {

        $sql = "SELECT profile_pic FROM accounts WHERE username = :username";
        $stmt = $this->db->prepare($sql);
        $stmt->bindParam(':username', $username);
        $stmt->execute();
        $avatar = $stmt->fetchColumn();
        if (empty($avatar)) {
            return 'default.png';  // Ensure this matches the file name in your assets
        }
        return $avatar;
    }

    // Logout
    public function logout()
    {

        if (isset($_SESSION['username'])) {
            $username = $_SESSION['username'];

            $stmt = $this->db->prepare("UPDATE accounts SET session_key = NULL, logged = 0 WHERE username = :username");
            $stmt->bindParam(':username', $username, PDO::PARAM_STR);
            $stmt->execute();

            $stmt = $this->db->prepare("UPDATE login_status SET logged_out = NOW() WHERE username = :username AND logged_out IS NULL ORDER BY id DESC LIMIT 1");
            $stmt->bindParam(':username', $username, PDO::PARAM_STR);
            $stmt->execute();
        }

        session_unset();
        session_destroy();

        setcookie('username', '', time() - 3600, "/");
        setcookie('session_key', '', time() - 3600, "/");
        setcookie(session_name(), '', time() - 3600, '/');
    }
}
