<?php
ini_set('session.gc_maxlifetime',5); //600
ini_set('session.gc_probability',100);
session_start();

if (!isset($_SESSION['user'])) {
    header('Location: login.php');
    exit;
}

if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['submit'])) {
    require_once 'Database.php';
    $db = new Database();
    $conn = $db->getConnection();

    $name = $_POST['name'];
    $phone = $_POST['phone'];
    $email = $_POST['email'];
    $old_password = $_POST['old_password'];
    $new_password = $_POST['new_password'];
    $confirm_new_password = $_POST['confirm_new_password'];

    $stmt = $conn->prepare("SELECT * FROM users WHERE id = :id");
    $stmt->bindParam(':id', $_SESSION['user']['id']);
    $stmt->execute();

    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($user['email'] !== $email && $user['phone'] !== $phone) {

        $stmt = $conn->prepare("SELECT * FROM users WHERE email = :email OR phone = :phone");
        $stmt->bindParam(':email', $email);
        $stmt->bindParam(':phone', $phone);
        $stmt->execute();

        if ($stmt->rowCount() > 0) {
            $_SESSION['error'] = 'Такой пользователь уже зарегистрирован';
            header('Location: profile.php');
            exit;
        }
    }

    if ($new_password !== '') {

        if (password_verify($old_password, $user['password'])) {

            if ($new_password !== $confirm_new_password) {
                $_SESSION['error'] = 'Пароли не совпадают';
                header('Location: profile.php');
                exit;
            }

            $hashed_password = password_hash($new_password, PASSWORD_DEFAULT);
            $stmt = $conn->prepare('UPDATE users SET password = :password WHERE id = :id');
            $stmt->bindParam(':password', $hashed_password);
            $stmt->bindParam(':id', $_SESSION['user']['id']);
            $stmt->execute();

            $_SESSION['success'] = 'Пароль успешно изменён';
        } else {
            $_SESSION['error'] = 'Неверный пароль';
            header('Location: profile.php');
            exit;
        }
    }

    $stmt = $conn->prepare('UPDATE users SET name = :name, phone = :phone, email = :email WHERE id = :id');
    $stmt->bindParam(':name', $name);
    $stmt->bindParam(':phone', $phone);
    $stmt->bindParam(':email', $email);
    $stmt->bindParam(':id', $_SESSION['user']['id']);

    if ($stmt->execute()) {
        $_SESSION['success'] = 'Данные успешно изменены';
        header('Location: profile.php');
        exit;
    } else {
        $_SESSION['error'] = 'Произошла ошибка при изменении данных';
        header('Location: profile.php');
        exit;
    }
}

if (isset($_SESSION['success'])) {
    echo '<div style="color:green">' . $_SESSION['success'] . '</div>';
    unset($_SESSION['success']);
}

if (isset($_SESSION['error'])) {
    echo '<div style="color:red">' . $_SESSION['error'] . '</div>';
    unset($_SESSION['error']);
}

require_once 'Database.php';
$db = new Database();
$conn = $db->getConnection();

$stmt = $conn->prepare('SELECT * FROM users WHERE id = :id');
$stmt->bindParam(':id', $_SESSION['user']['id']);
$stmt->execute();

$user = $stmt->fetch(PDO::FETCH_ASSOC);
?>
<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="UTF-8">
        <title><?= $user['name'] ?></title>
    </head>
    <body>
        <h1>Профиль пользователя</h1>
        <form method="POST">
            <label for="name">Имя</label>
            <input id="name" type="text" name="name" value="<?= $user['name'] ?>" required><br/>

            <label for="phone">Телефон</label>
            <input id="phone" type="tel" name="phone" value="<?= $user['phone'] ?>" pattern="[0-9]{10}" required><br/>

            <label for="email">Почта</label>
            <input id="email" type="email" name="email" value="<?= $user['email'] ?>" required><br/>

            <label for="old_password">Старый пароль</label>
            <input id="old_password" type="password" name="old_password"><br/>

            <label for="new_password">Новый пароль</label>
            <input id="new_password" type="password" name="new_password"><br/>

            <label for="confirm_new_password">Повторите новый пароль</label>
            <input id="confirm_new_password" type="password" name="confirm_new_password"><br/>

            <input type="submit" name="submit" value="Сохранить">
        </form>
        <br>
        <a href="index.php">Вернуться на главную страницу</a>
        <br>
        <a href="logout.php">Выйти</a>
    </body>
</html>