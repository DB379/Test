<?php
session_start();
require_once __DIR__ . '/../models/User.php';
require_once __DIR__ . '/../secure/config.php';



function sendJsonResponse($success, $message = '', $data = []) {
    header('Content-Type: application/json');
    echo json_encode(array_merge(
        ['success' => $success, 'message' => $message],
        $data
    ));
    exit;
}

try {
    if (!isset($_SESSION['username'])) {
        throw new Exception('User not logged in.');
    }

    $username = $_SESSION['username'];
    $selectedAvatar = $_POST['selected-avatar'] ?? null;

    if (!$selectedAvatar) {
        throw new Exception('No avatar selected.');
    }

    $userModel = new User($db);
    $result = $userModel->updateAvatar($username, $selectedAvatar);

    if ($result === false) {
        throw new Exception('Failed to update avatar in the database.');
    }

    sendJsonResponse(true, 'Avatar updated successfully.', ['avatar' => $selectedAvatar]);
} catch (Exception $e) {
    error_log('Avatar update error: ' . $e->getMessage());
    sendJsonResponse(false, 'Error: ' . $e->getMessage());
}
