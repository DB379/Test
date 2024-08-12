<?php

class SettingsController
{
    private $userModel;

    public function __construct($userModel) {
        $this->userModel = $userModel;
    }

    public function handleRequest()
    {
        session_start(); // Start session management

        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            if (isset($_POST['change_password'])) {
                $this->changePassword();
            }

            if (isset($_POST['change_email'])) {
                $this->changeEmail();
            }

            header('Location: ../index.php?page=settings/security');
            exit();
        }
    }

    private function changePassword()
    {
        $oldPassword = $_POST['old-password'];
        $newPassword = $_POST['new-password'];
        $retypePassword = $_POST['retype-password'];

        if ($newPassword === $oldPassword) {
            $_SESSION['password_error'] = "New password cannot be the same as the old password!";
        } elseif ($newPassword !== $retypePassword) {
            $_SESSION['password_error'] = "New passwords do not match!";
        } elseif (!$this->userModel->validatePassword($newPassword)) {
            $_SESSION['password_error'] = "New password does not meet requirements!";
        } else {
            $result = $this->userModel->changePassword($_SESSION['username'], $oldPassword, $newPassword);
            if ($result) {
                $_SESSION['password_success'] = "Password changed successfully!";
            } else {
                $_SESSION['password_error'] = "Failed to change password. Please check your old password and try again.";
            }
        }
    }

    private function changeEmail()
    {
        $oldEmail = $_POST['old-email'];
        $newEmail = $_POST['new-email'];
        $retypeEmail = $_POST['retype-email'];

        $allowedDomains = ['hotmail.com', 'outlook.com', 'gmail.com'];
        $emailDomain = substr(strrchr($newEmail, "@"), 1);

        if ($newEmail === $oldEmail) {
            $_SESSION['email_error'] = "New email cannot be the same as the old email!";
        } elseif ($newEmail !== $retypeEmail) {
            $_SESSION['email_error'] = "New emails do not match!";
        } elseif (!in_array($emailDomain, $allowedDomains)) {
            $_SESSION['email_error'] = "Email must be from hotmail, outlook, or gmail.";
        } elseif (!$this->userModel->validateEmail($newEmail)) {
            $_SESSION['email_error'] = "Invalid email format!";
        } else {
            $result = $this->userModel->changeEmail($_SESSION['username'], $oldEmail, $newEmail);
            if ($result) {
                $_SESSION['email_success'] = "Email changed successfully!";
            } else {
                $_SESSION['email_error'] = "Failed to change email. Please check your old email and try again.";
            }
        }
    }
    
}
