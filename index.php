<?php
session_set_cookie_params([
    'lifetime' => 7200,
    'path' => '/',
    'domain' => '',
    'secure' => isset($_SERVER['HTTPS']),
    'httponly' => true,
    'samesite' => 'Strict'
]);

session_start();

require 'secure/db.php';  // Assuming this contains configuration constants
require 'secure/database.php';   // Path to your singleton Database class

// Instantiate the database connection
$db = Database::getInstance()->getConnection();

require 'models/User.php';
require 'models/NavigationModel.php';
require 'controllers/LoginController.php';
require 'controllers/RegisterController.php';
require 'controllers/NavigationController.php';
require 'controllers/SettingsController.php';



// Pass the database connection to models and controllers
$userModel = new User($db);
$navigationModel = new NavigationModel($db);
$loginController = new LoginController($userModel);
$registerController = new RegisterController($userModel);
$settingsController = new SettingsController($userModel); 
$navigationController = new NavigationController($navigationModel, $loginController, $registerController, $userModel);

$page = isset($_GET['page']) ? $navigationModel->sanitizeInput($_GET['page']) : 'dashboard';
$navigationController->route($page, $settingsController);