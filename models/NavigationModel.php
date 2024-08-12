<?php


class NavigationModel {
    private $db;

    public function __construct($db) {
        $this->db = $db;
    }

    public function isLoggedIn() {
        return isset($_SESSION['username']);
    }

    public function getUserRole($username) {
        $stmt = $this->db->prepare("SELECT level FROM accounts WHERE username = :username");
        $stmt->bindParam(':username', $username, PDO::PARAM_STR);
        $stmt->execute();
        return $stmt->fetchColumn();
    }

    public function sanitizeInput($input) {
        return htmlspecialchars(strip_tags(trim($input)));
    }

    public function getUsername() {
        return $this->sanitizeInput($_SESSION['username']);
    }

    public function getAllowedPages() {
        return [
            'dashboard' => 0,
            'acc' => 0,
            'mail' => 0,
            'settings' => 0,
            'logout' => 0,
            'mods' => 1,
            'officers' => 2,
            'admin' => 3
        ];
    }

    public function checkPageAccess($page, $role) {
        $allowedPages = $this->getAllowedPages();
        return isset($allowedPages[$page]) && $role >= $allowedPages[$page];
    }

    public function logout() {
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
