<?php
ini_set('session.gc_maxlifetime',5); //600
ini_set('session.gc_probability',100);
session_start();
require_once 'Database.php';

if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['submit'])) {
    $name = $_POST['name'];
    $phone = $_POST['phone'];
    $email = $_POST['email'];
    $password = $_POST['password'];
    $confirm_password = $_POST['confirm_password'];

    $db = new Database();
    $conn = $db->getConnection();

    $stmt = $conn->prepare("SELECT * FROM users WHERE email = :email OR phone = :phone");
    $stmt->bindParam(':email', $email);
    $stmt->bindParam(':phone', $phone);
    $stmt->execute();

    if ($stmt->rowCount() > 0) {
        $_SESSION['error'] = 'Такой пользователь уже зарегистрирован';
        header('Location: registration.php');
        exit;
    }

    if ($password !== $confirm_password) {
        $_SESSION['error'] = 'Пароли не совпадают';
        header('Location: registration.php');
        exit;
    }

    $hashed_password = password_hash($password, PASSWORD_DEFAULT);

    $stmt = $conn->prepare("INSERT INTO users (name, phone, email, password) VALUES (:name, :phone, :email, :password)");
    $stmt->bindParam(':name', $name);
    $stmt->bindParam(':phone', $phone);
    $stmt->bindParam(':email', $email);
    $stmt->bindParam(':password', $hashed_password);

    if ($stmt->execute()) {
        $_SESSION['success'] = 'Вы успешно зарегистрировались';
        header('Location: login.php');
        exit;
    } else {
        $_SESSION['error'] = 'Произошла ошибка при регистрации';
        header('Location: registration.php');
        exit;
    }
}
?>
<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Регистрация</title>
    </head>
    <body>
        <?php if (isset($_SESSION['error'])): ?>
            <div style="color: red"><?= $_SESSION['error'] ?></div>
            <?php unset($_SESSION['error']); ?>
        <?php endif; ?>
        <form method="POST">
            <label for="name">Имя</label>
            <input id="name" type="text" name="name" required><br/>

            <label for="phone">Телефон</label>
            <input id="phone" type="tel" name="phone" pattern="[0-9]{10}" required><br/>

            <label for="email">Почта</label>
            <input id="email" type="email" name="email" required><br/>

            <label for="password">Пароль</label>
            <input id="password" type="password" name="password" required><br/>

            <label for="confirm_password">Повторите пароль</label>
            <input id="confirm_password" type="password" name="confirm_password" required><br/>

            <input type="submit" name="submit" value="Зарегистрироваться">
        </form>
    </body>
</html>