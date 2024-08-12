<?php

class NavigationController
{
    private $navigationModel;
    private $loginController;
    private $registerController;
    private $userModel;

    public function __construct($navigationModel, $loginController, $registerController, $userModel)
{
    $this->navigationModel = $navigationModel;
    $this->loginController = $loginController;
    $this->registerController = $registerController;
    $this->userModel = $userModel;

    
}

public function route($page, SettingsController $settingsController) {
    
    if ($page === 'changes' && $_SERVER['REQUEST_METHOD'] === 'POST') {
      $settingsController->handleRequest();
    }

    if (!$this->navigationModel->isLoggedIn() && !in_array($page, ['login', 'register'])) {
        header('Location: index.php?page=login');
        exit();
    }

        $subpage = '';

        if (strpos($page, '/') !== false) {
            list($page, $subpage) = explode('/', $page);
        }

        try {
            switch ($page) {
                case 'logout':
                    $this->logout();
                    break;
                case 'dashboard':
                case 'acc':
                case 'mail':
                case 'mods':
                case 'officers':
                case 'admin':
                case 'settings':
                    $this->showDashboard($page, $subpage);
                    break;
                case 'login':
                    $this->loginController->login();
                    break;
                case 'register':
                    $this->registerController->register();
                    break;
                case 'changes':
                    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
                        include __DIR__ . '/../controllers/SettingsController.php';
                    }
                    break;
                default:
                    header('Location: index.php?page=dashboard');
                    break;
            }
        } catch (Exception $e) {
            error_log("Error in routing: " . $e->getMessage());
            header('Location: index.php?page=login');
            exit();
        }
    }

    public function showDashboard($page = 'dashboard', $subpage = '')
    {
        $this->userModel->regenerateCSRFToken();
        
        $username = $this->navigationModel->getUsername();
        $role = $this->navigationModel->getUserRole($username);

        if ($role === null) {
            echo "Error fetching user role.";
            exit();
        }

        $currentPage = $page;
        $currentSubpage = $subpage;
        $pages = [
            'dashboard' => ['title' => 'Dashboard', 'role' => 0],
            'acc' => ['title' => 'Accounts', 'role' => 0],
            'mail' => ['title' => 'Email', 'role' => 0],
            'mods' => ['title' => 'Moderators', 'role' => 1],
            'officers' => ['title' => 'Officers', 'role' => 2],
            'admin' => ['title' => 'Admin', 'role' => 3]
        ];

        switch ($currentPage) {
            case 'acc':
                $contentPage = 'public/acc.php';
                break;
            case 'mail':
                $contentPage = 'public/mail.php';
                break;
            case 'settings':
                $contentPage = 'private/settings.php';
                break;
            case 'mods':
                if ($role >= 1) {
                    $contentPage = 'public/mods.php';
                } else {
                    $this->redirectUnauthorized();
                }
                break;
            case 'officers':
                if ($role >= 2) {
                    $contentPage = 'public/officers.php';
                } else {
                    $this->redirectUnauthorized();
                }
                break;
            case 'admin':
                if ($role >= 3) {
                    $contentPage = 'public/admin.php';
                } else {
                    $this->redirectUnauthorized();
                }
                break;
            case 'dashboard':
            default:
                $contentPage = 'public/dashboard.php';
                break;
        }

        // Pass the variables to the view using an associative array
        $data = compact('username', 'role', 'currentPage', 'currentSubpage', 'pages', 'contentPage');
        $this->renderView('dashboard', $data);
    }

    private function renderView($view, $data)
    {
        extract($data);
        include __DIR__ . "/../views/{$view}.php";
    }

    private function redirectUnauthorized()
    {
        header('Location: index.php?page=dashboard');
        exit();
    }

    public function logout()
    {
        $this->navigationModel->logout();
        header('Location: index.php?page=login');
        exit();
    }
}
