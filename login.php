<?php
session_start();
require_once 'Database.php';

if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['submit'])) {
    $login = $_POST['login'];
    $password = $_POST['password'];
    $recaptcha_secret = 'Ваш_reCAPTCHA_секретный_ключ';

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, 'https://www.google.com/recaptcha/api/siteverify');
    curl_setopt($ch, CURLOPT_POST, 1);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query([
        'secret' => $recaptcha_secret,
        'response' => $_POST['g-recaptcha-response']
    ]));
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

    $response = json_decode(curl_exec($ch), true);

    curl_close($ch);

    if ($response['success'] == true) { //!== 
        $_SESSION['error'] = 'Вы не прошли проверку reCAPTCHA';
        header('Location: login.php');
        exit;
    }

    $db = new Database();
    $conn = $db->getConnection();

    $stmt = $conn->prepare("SELECT * FROM users WHERE email = :login OR phone = :login");
    $stmt->bindParam(':login', $login);
    $stmt->execute();

    if ($stmt->rowCount() === 0) {
        $_SESSION['error'] = 'Пользователь с таким логином не найден';
        header('Location: login.php');
        exit;
    }

    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if (password_verify($password, $user['password'])) {
        $_SESSION['user'] = $user;
        header('Location: profile.php');
        exit;
    } else {
        $_SESSION['error'] = 'Неверный логин или пароль';
        header('Location: login.php');
        exit;
    }
}
?>
<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Авторизация</title>
        <script src="https://www.google.com/recaptcha/api.js" async defer></script>

    </head>
    <body>
        <?php if (isset($_SESSION['error'])): ?>
            <div style="color: red"><?= $_SESSION['error'] ?></div>
            <?php unset($_SESSION['error']); ?>
        <?php endif; ?>
        <form method="POST">
            <label for="login">Телефон или почта</label>
            <input id="login" type="text" name="login" required><br/>

            <label for="password">Пароль</label>
            <input id="password" type="password" name="password" required><br/>

            <div class="g-recaptcha" data-sitekey="6LfD3PIbAAAAAJs_eEHvoOl75_83eXSqpPSRFJ_u"></div>
            <br/>

            <input type="submit" name="submit" value="Войти">
        </form>
        <br>
        <a href="index.php">Вернуться на главную страницу</a>
    </body>
</html>