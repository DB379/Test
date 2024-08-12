<?php
// LoginController.php

class LoginController {
    private $userModel;
    private $sessionTimeout = 3600; // 1 hour for "Remember Me"

    public function __construct($userModel) {
        $this->userModel = $userModel;
        $this->checkSessionTimeout();
    }

    

    public function showLoginForm() {
        $this->userModel->regenerateCSRFToken();
        require 'private/login.php';
    }

    public function login() {
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $csrf_token = $_POST['csrf_token'] ?? '';
            if (!$this->userModel->validateCsrfToken($csrf_token)) {
                $this->handleFormError("Invalid CSRF token.", "login");
            }
    
            $username = $this->userModel->sanitizeInput($_POST['username']);
            $password = $this->userModel->sanitizeInput($_POST['password']);
            $remember_me = isset($_POST['remember_me']);
    
            if (!$this->userModel->validateUsername($username) || !$this->userModel->validatePassword($password)) {
                $this->handleFormError("Invalid input.", "login");
            }
    
            try {
                $this->userModel->checkRateLimit();
                $user = $this->userModel->authenticate($username, $password);
    
                if ($user) {
                    $status = $this->userModel->checkUserStatus($username);
                    switch ($status) {
                        case 0:
                            $this->handleSuccessfulLogin($username, $remember_me);
                            break;
                        case 1:
                            $this->handleFormError("Your account has been muted!", "login");
                        case 2:
                            $this->handleFormError("Account locked by Administrator", "login");
                        case 3:
                            $this->handleFormError("Account banned permanently", "login");
                        default:
                            $this->handleFormError("Unknown account status", "login");
                    }
                } else {
                    $this->userModel->incrementFailedLogin($username);
                    $this->handleFormError("Invalid username or password.", "login");
                }
            } catch (Exception $e) {
                $this->handleFormError($e->getMessage(), "login");
            }
        } else {
            $this->showLoginForm();
        }
    }

    private function handleSuccessfulLogin($username, $remember_me) {
        session_regenerate_id(true);
        $session_key = $this->userModel->generateSessionKey($username);
        $_SESSION['username'] = $username;
        $_SESSION['session_key'] = $session_key;
        $_SESSION['last_activity'] = time();
        $_SESSION['remember_me'] = $remember_me;

        $this->userModel->setLoggedStatus($username, 1);

        if ($remember_me) {
            setcookie('username', $username, time() + $this->sessionTimeout, "/", "", isset($_SERVER['HTTPS']), true);
            setcookie('session_key', $session_key, time() + $this->sessionTimeout, "/", "", isset($_SERVER['HTTPS']), true);
        } else {
            setcookie('username', $username, 0, "/", "", isset($_SERVER['HTTPS']), true);
            setcookie('session_key', $session_key, 0, "/", "", isset($_SERVER['HTTPS']), true);
        }

        $this->userModel->clearLoginAttempts();
        $this->userModel->regenerateCSRFToken();

        header('Location: index.php?page=dashboard');
        exit();
    }

    private function handleFormError($message, $redirect) {
        $_SESSION['login_error'] = $message;
        $this->userModel->regenerateCSRFToken();
        header("Location: ../index.php?page=$redirect");
        exit();
    }

    private function checkSessionTimeout() {
        if (isset($_SESSION['last_activity'])) {
            // Set default timeout if remember_me is not set
            $timeout = isset($_SESSION['remember_me']) && $_SESSION['remember_me'] ? $this->sessionTimeout : 3600;
            
            if ((time() - $_SESSION['last_activity']) > $timeout) {
                $this->userModel->logout();
            }
        }
        $_SESSION['last_activity'] = time();
    }
}