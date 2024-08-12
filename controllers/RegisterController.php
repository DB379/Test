<?php

class RegisterController {
    private $userModel;

    public function __construct($userModel) {
        $this->userModel = $userModel;
    }

    public function showRegisterForm() {
        $this->userModel->regenerateCSRFToken(); // Assuming this method sets the CSRF token in the session
        require 'private/register.php';
    }

    public function register() {
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $csrf_token = $_POST['csrf_token'] ?? '';
            if (!$this->userModel->validateCsrfToken($csrf_token)) {
                $_SESSION['login_error'] = "Invalid CSRF token.";
                header('Location: ../index.php?page=login');
                exit();
            }
        
            $username = $this->userModel->sanitizeInput($_POST['username']);
            $email = $this->userModel->sanitizeInput($_POST['email']);
            $password = $this->userModel->sanitizeInput($_POST['password']);
            $password_confirm = $this->userModel->sanitizeInput($_POST['password_confirm']);

            if (!$this->userModel->validateUsername($username) || !$this->userModel->validateEmail($email) || !$this->userModel->validatePassword($password)) {
                $_SESSION['register_error'] = "Invalid input.";
                header('Location: index.php?page=register');
                exit();
            }

            // Check for duplicate username or email
            if ($this->userModel->isUsernameTaken($username)) {
                $_SESSION['register_error'] = "Username already in use.";
                header('Location: index.php?page=register');
                exit();
            }
            if ($this->userModel->isEmailTaken($email)) {
                $_SESSION['register_error'] = "Email already in use.";
                header('Location: index.php?page=register');
                exit();
            }

            if ($password === $password_confirm) {
                try {
                    if ($this->userModel->register($username, $email, $password)) {
                        $_SESSION['register_success'] = "Registration successful!";
                        $_SESSION['csrf_token'] = $this->userModel->generateCsrfToken(); // Generate new token after registration
                        header('Location: index.php?page=register');
                        exit();
                    } else {
                        $_SESSION['register_error'] = "Registration failed.";
                        header('Location: index.php?page=register');
                        exit();
                    }
                } catch (Exception $e) {
                    error_log("Exception during registration: " . $e->getMessage());
                    $_SESSION['register_error'] = "An error occurred. Please try again.";
                    header('Location: index.php?page=register');
                    exit();
                }
            } else {
                $_SESSION['register_error'] = "Passwords don't match.";
                header('Location: index.php?page=register');
                exit();
            }
        } else {
            $this->showRegisterForm(); // Show the registration form and generate CSRF token
        }
    }
}
?>
