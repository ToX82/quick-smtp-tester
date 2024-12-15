<?php
$status = init();
$config = get_config();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Quick SMTP Tester</title>
    <link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>📧</text></svg>">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container py-3">
        <h2 class="text-center mb-3">📧 Quick SMTP Tester</h2>
        <h6 class="text-center mb-3">Because testing SMTP settings should be quick (and easy)</h6>
        <div class="alert alert-warning py-2" role="alert">
            ⚠️ Remember to remove this file after testing for security reasons!
        </div>

        <form method="post" class="mb-3 p-3 bg-light rounded shadow-sm">
            <div class="row g-2">
                <div class="col-md-6">
                    <label for="from" class="form-label small fw-bold">From Address</label>
                    <input type="email" class="form-control form-control-sm" id="from" name="from" required value="<?php echo htmlspecialchars(isset($config['from']) ? $config['from'] : ''); ?>" placeholder="Your email address">
                </div>
                <div class="col-md-6">
                    <label for="to" class="form-label small fw-bold">To Address</label>
                    <input type="email" class="form-control form-control-sm" id="to" name="to" required value="<?php echo htmlspecialchars(isset($config['to']) ? $config['to'] : ''); ?>" placeholder="Where to send the test?">
                </div>

                <div class="col-12">
                    <label for="subject" class="form-label small fw-bold">Email Subject</label>
                    <input type="text" class="form-control form-control-sm" id="subject" name="subject" required value="<?php echo htmlspecialchars(isset($config['subject']) ? $config['subject'] : ''); ?>" placeholder="Enter your subject line">
                </div>

                <div class="col-12">
                    <label for="message" class="form-label small fw-bold">Email Content</label>
                    <textarea class="form-control form-control-sm" id="message" name="message" rows="3" required placeholder="Write your test message here"><?php echo htmlspecialchars(isset($config['message']) ? $config['message'] : ''); ?></textarea>
                </div>

                <div class="col-md-3">
                    <label for="smtpHost" class="form-label small fw-bold">SMTP Server</label>
                    <input type="text" class="form-control form-control-sm" id="smtpHost" name="smtpHost" required value="<?php echo htmlspecialchars(isset($config['smtpHost']) ? $config['smtpHost'] : ''); ?>" placeholder="e.g. smtp.myhost.com">
                </div>
                <div class="col-md-3">
                    <label for="smtpPort" class="form-label small fw-bold">Port</label>
                    <select class="form-select form-select-sm" id="smtpPort" name="smtpPort" required>
                        <option value="587" <?php echo (isset($config['smtpPort']) && $config['smtpPort'] == 587) ? 'selected' : ''; ?>>587 (TLS - Recommended)</option>
                        <option value="465" <?php echo (isset($config['smtpPort']) && $config['smtpPort'] == 465) ? 'selected' : ''; ?>>465 (SSL)</option>
                        <option value="25" <?php echo (isset($config['smtpPort']) && $config['smtpPort'] == 25) ? 'selected' : ''; ?>>25 (Standard)</option>
                        <option value="2525" <?php echo (isset($config['smtpPort']) && $config['smtpPort'] == 2525) ? 'selected' : ''; ?>>2525 (Alternative)</option>
                    </select>
                </div>
                <div class="col-md-3">
                    <label for="security" class="form-label small fw-bold">Security</label>
                    <select class="form-select form-select-sm" id="security" name="security" required>
                        <option value="tls" <?php echo (isset($config['security']) && $config['security'] == 'tls') ? 'selected' : ''; ?>>TLS (Recommended)</option>
                        <option value="ssl" <?php echo (isset($config['security']) && $config['security'] == 'ssl') ? 'selected' : ''; ?>>SSL</option>
                        <option value="none" <?php echo (isset($config['security']) && $config['security'] == 'none') ? 'selected' : ''; ?>>None</option>
                    </select>
                </div>
                <div class="col-md-3">
                    <label for="allow_self_signed" class="form-label small fw-bold">Self-signed Certificates</label>
                    <select class="form-select form-select-sm" id="allow_self_signed" name="allow_self_signed" required>
                        <option value="0" <?php echo (isset($config['allow_self_signed']) && $config['allow_self_signed'] === false) ? 'selected' : ''; ?>>Don't allow</option>
                        <option value="1" <?php echo (isset($config['allow_self_signed']) && $config['allow_self_signed'] === true) ? 'selected' : ''; ?>>Allow</option>
                    </select>
                </div>

                <div class="col-md-6">
                    <label for="smtpUser" class="form-label small fw-bold">SMTP Username</label>
                    <input type="text" class="form-control form-control-sm" id="smtpUser" name="smtpUser" required value="<?php echo htmlspecialchars(isset($config['smtpUser']) ? $config['smtpUser'] : ''); ?>" placeholder="Your SMTP username">
                </div>
                <div class="col-md-6">
                    <label for="smtpPass" class="form-label small fw-bold">SMTP Password</label>
                    <div class="input-group input-group-sm">
                        <input type="password" class="form-control" id="smtpPass" name="smtpPass" required value="<?php echo htmlspecialchars(isset($config['smtpPass']) ? $config['smtpPass'] : ''); ?>" placeholder="Your SMTP password">
                        <button class="btn btn-outline-secondary" type="button" onclick="togglePassword()">Show</button>
                    </div>
                </div>

                <div class="col-md-6 offset-md-3 d-flex align-items-end">
                    <button type="submit" name="submit" class="btn btn-primary btn-sm w-100">✉️ Send Test Email</button>
                </div>
            </div>

            <?php if ($status !== null) { ?>
                <div class="mt-3 alert <?php echo strpos($status, 'success') !== false ? 'alert-success' : 'alert-danger'; ?> py-2 mb-0">
                    <?php if (strpos($status, 'success') !== false) { ?>
                        🎉 Great! Your test email was sent successfully!
                    <?php } else { ?>
                        <div class="mb-2">😕 Oops! Something went wrong:</div>
                        <pre class="mb-2 small bg-light p-2 rounded"><?php echo htmlspecialchars($status); ?></pre>
                        <div class="small text-muted mb-2">Debug information:</div>
                        <pre class="mb-2 small bg-light p-2 rounded"><?php echo htmlspecialchars(print_r(error_get_last(), true)); ?></pre>
                        <a href="https://www.perplexity.ai/search/?q=<?php echo urlencode($status) . urlencode(print_r(error_get_last(), true)); ?>" target="_blank" class="btn btn-sm btn-primary">Find a Solution</a>
                    <?php } ?>
                </div>
            <?php } ?>
        </form>
    </div>

    <script>
    function togglePassword() {
        const passField = document.getElementById('smtpPass');
        const btn = passField.nextElementSibling;
        if (passField.type === 'password') {
            passField.type = 'text';
            btn.textContent = 'Hide';
        } else {
            passField.type = 'password';
            btn.textContent = 'Show';
        }
    }
    </script>
</body>
</html>

<?php
/**
 * |__| |__  |__) |__     |__) |__     |  \ |__)  /\  / _` /  \ |\ | /__`
 * |  | |___ |  \ |___    |__) |___    |__/ |  \ /~~\ \__> \__/ | \| .__/
 *
 * From here on lies the connection logic and testing.
 * No need to modify anything beyond this point.
 */

/**
 * Initialize SMTP test functionality and handle form submission.
 *
 * This function handles the SMTP test form submission by:
 * - Starting a session if not already started
 * - Validating and sanitizing input data
 * - Saving configuration to session
 * - Attempting to send a test email via SMTP
 *
 * @return string|null Returns error message on failure, success message on success, or null if no submission
 */
function init()
{
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }

    if (!isset($_POST['submit'])) {
        return null;
    }

    // Validate and clean input data
    $from = filter_input(INPUT_POST, 'from', FILTER_SANITIZE_EMAIL);
    $to = filter_input(INPUT_POST, 'to', FILTER_SANITIZE_EMAIL);
    $subject = filter_input(INPUT_POST, 'subject', FILTER_SANITIZE_STRING);
    $message = filter_input(INPUT_POST, 'message', FILTER_SANITIZE_STRING);
    $smtpHost = filter_input(INPUT_POST, 'smtpHost', FILTER_SANITIZE_STRING);
    $smtpPort = filter_input(INPUT_POST, 'smtpPort', FILTER_VALIDATE_INT);
    $smtpUser = filter_input(INPUT_POST, 'smtpUser', FILTER_SANITIZE_STRING);
    $smtpPass = filter_input(INPUT_POST, 'smtpPass', FILTER_SANITIZE_STRING);
    $security = filter_input(INPUT_POST, 'security', FILTER_SANITIZE_STRING);
    $allow_self_signed = filter_input(INPUT_POST, 'allow_self_signed', FILTER_VALIDATE_BOOLEAN);

    // Save cleaned data in session
    $config = array(
        'from' => $from,
        'to' => $to,
        'subject' => $subject,
        'message' => $message,
        'smtpHost' => $smtpHost,
        'smtpPort' => $smtpPort,
        'smtpUser' => $smtpUser,
        'smtpPass' => $smtpPass,
        'security' => $security,
        'allow_self_signed' => $allow_self_signed
    );
    $_SESSION['smtpConfig'] = $config;

    try {
        return smtp_mail(
            $to,
            $subject,
            $message . " \n\n" . date('Y-m-d H:i:s'),
            $from,
            "From: $from\r\nTo: $to",
            $smtpHost,
            $smtpPort,
            $smtpUser,
            $smtpPass,
            $security,
            $allow_self_signed
        );
    } catch (Exception $e) {
        return $e->getMessage();
    }
}

/**
 * Send an email using a specified SMTP server.
 *
 * @param string $to Email recipient.
 * @param string $subject Email subject.
 * @param string $message Email body.
 * @param string $from Sender's email address.
 * @param string $headers Additional email headers.
 * @param string $smtp_server SMTP server to use.
 * @param int $smtp_port SMTP server port.
 * @param string $smtp_user Username for SMTP authentication.
 * @param string $smtp_pass Password for SMTP authentication.
 * @param string $security Security type (tls, ssl, none).
 * @param bool $allow_self_signed Whether to allow self-signed certificates.
 * @throws Exception If SMTP server connection fails or if there are errors during sending.
 */
function smtp_mail($to, $subject, $message, $from, $headers, $smtp_server, $smtp_port, $smtp_user, $smtp_pass, $security, $allow_self_signed = false)
{
    $context = stream_context_create();
    if ($allow_self_signed) {
        stream_context_set_option($context, 'ssl', 'allow_self_signed', true);
    }

    $socket = stream_socket_client(
        "tcp://{$smtp_server}:{$smtp_port}",
        $errno,
        $errstr,
        30,
        STREAM_CLIENT_CONNECT,
        $context
    );

    if (!$socket) {
        throw new Exception("Could not connect to SMTP server: $errstr ($errno)");
    }

    fread($socket, 512);

    send_cmd($socket, "EHLO " . gethostname(), "250");

    if ($security === 'tls' || $security === 'ssl') {
        $crypto_method = $security === 'tls' ? STREAM_CRYPTO_METHOD_TLS_CLIENT : STREAM_CRYPTO_METHOD_SSLv23_CLIENT;
        send_cmd($socket, "STARTTLS", "220");
        stream_socket_enable_crypto($socket, true, $crypto_method);
        send_cmd($socket, "EHLO " . gethostname(), "250");
    }

    send_cmd($socket, "AUTH LOGIN", "334");
    send_cmd($socket, base64_encode($smtp_user), "334");
    send_cmd($socket, base64_encode($smtp_pass), "235");

    send_cmd($socket, "MAIL FROM: <" . $from . ">", "250");
    send_cmd($socket, "RCPT TO: <" . $to . ">", "250");
    send_cmd($socket, "DATA", "354");

    // Determine content type and prepare email body
    $content_type = "text/plain; charset=UTF-8";
    $message_id = '<' . time() . '.' . md5(uniqid(rand(), true)) . '@' . gethostname() . '>';
    $date = date('r');

    // Add Received headers to track email path
    $received_headers = "Received: from " . gethostname() . " (" . $_SERVER['SERVER_ADDR'] . ")\r\n";
    $received_headers .= "\tby " . $smtp_server . " with SMTP\r\n";
    $received_headers .= "\tid " . $message_id . "\r\n";
    $received_headers .= "\tfor <" . $to . ">; " . $date . "\r\n";

    $email_body = "Subject: $subject\r\n";
    $email_body .= "Content-Type: $content_type\r\n";
    $email_body .= "Message-ID: $message_id\r\n";
    $email_body .= "Date: $date\r\n";
    $email_body .= $received_headers;
    if (!empty($headers)) {
        $email_body .= $headers . "\r\n";
    }
    $email_body .= "\r\n" . $message;

    fwrite($socket, $email_body . "\r\n.\r\n");

    $response = fread($socket, 512);
    if (strpos($response, "250") !== 0) {
        // Read any additional data from socket
        $additional_response = '';
        while ($data = @fread($socket, 512)) {
            $additional_response .= $data;
            if (substr($data, -2) === "\r\n") {
                break;
            }
        }

        // Prepare detailed error message
        $error_details = "SMTP Error while sending email:\n";
        $error_details .= "- Initial response: " . trim($response) . "\n";
        if ($additional_response) {
            $error_details .= "- Additional details: " . trim($additional_response) . "\n";
        }
        return $error_details;
    }

    send_cmd($socket, "QUIT", "221");
    fclose($socket);

    return "success";
}

/**
 * Send a command to the SMTP server and verify the response.
 *
 * @param resource $socket The SMTP server connection socket.
 * @param string $cmd The command to send.
 * @param string $expected_response The expected server response.
 * @throws Exception If server response doesn't match expected response.
 */
function send_cmd($socket, $cmd, $expected_response)
{
    fwrite($socket, $cmd . "\r\n");
    $response = fread($socket, 512);
    if (strpos($response, $expected_response) !== 0) {
        return $response;
    }
}

/**
 * Retrieves SMTP configuration from session storage or returns default values.
 *
 * @return array Associative array containing SMTP configuration with the following fields:
 *               - from: sender email address
 *               - to: recipient email address
 *               - subject: email subject
 *               - message: email body
 *               - smtpHost: SMTP server hostname
 *               - smtpPort: SMTP server port (default: 587)
 *               - smtpUser: SMTP authentication username
 *               - smtpPass: SMTP authentication password
 *               - security: security type (default: tls)
 *               - allow_self_signed: allow self-signed certificates
 */
function get_config()
{
    $config = isset($_SESSION['smtpConfig']) ? $_SESSION['smtpConfig'] : array(
        'from' => '',
        'to' => '',
        'subject' => 'Test subject',
        'message' => 'Hello, this is a test email.',
        'smtpHost' => '',
        'smtpPort' => '587',
        'smtpUser' => '',
        'smtpPass' => '',
        'security' => 'tls',
        'allow_self_signed' => false
    );

    return $config;
}
