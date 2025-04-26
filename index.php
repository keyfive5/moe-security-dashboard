<?php
// Moe Basha's Security Dashboard for Taylor Publishing Group

// Fetch headers for a given URL
function fetch_headers_info($url) {
    $headers = @get_headers($url, 1);
    return $headers ?: [];
}

// Analyze missing security headers
function analyze_security_headers($headers) {
    $required = [
        'Content-Security-Policy'   => false,
        'X-Frame-Options'           => false,
        'X-Content-Type-Options'    => false,
        'Referrer-Policy'           => false,
        'Permissions-Policy'        => false,
        'Strict-Transport-Security' => false,
    ];
    foreach ($required as $headerName => &$present) {
        foreach ($headers as $name => $value) {
            if (strcasecmp($name, $headerName) === 0) {
                $present = true;
                break;
            }
        }
    }
    return $required;
}

// Determine the URL to scan (default: powerboating.com)
$url = isset($_GET['url']) ? trim($_GET['url']) : 'https://www.powerboating.com';
if (!preg_match('/^https?:\/\//', $url)) {
    $url = 'https://' . $url;
}

// Get headers and analysis
$headers = fetch_headers_info($url);
$analysis = analyze_security_headers($headers);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Moe Basha's Security Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; line-height: 1.4; }
        h1 { color: #004080; }
        form { margin-bottom: 20px; }
        input[type="text"] { padding: 8px; width: 300px; }
        button { padding: 8px 12px; background: #004080; color: #fff; border: none; cursor: pointer; }
        table { border-collapse: collapse; width: 100%; margin-top: 20px; }
        th, td { border: 1px solid #ccc; padding: 10px; text-align: left; }
        th { background: #eef; }
        .present { color: green; font-weight: bold; }
        .missing { color: red; font-weight: bold; }
        pre { background: #f4f4f4; padding: 10px; overflow: auto; }
    </style>
</head>
<body>
    <h1>Moe Basha's Security Dashboard</h1>
    <p><em>Security status overview for Taylor Publishing Group websites.</em></p>
    <form method="get">
        <label>Website URL: <input type="text" name="url" value="<?php echo htmlspecialchars($url); ?>" /></label>
        <button type="submit">Scan</button>
    </form>
    <h2>Header Analysis for <?php echo htmlspecialchars($url); ?></h2>
    <table>
        <tr><th>Header</th><th>Status</th></tr>
        <?php foreach ($analysis as $headerName => $isPresent): ?>
        <tr>
            <td><?php echo $headerName; ?></td>
            <td class="<?php echo $isPresent ? 'present' : 'missing'; ?>">
                <?php echo $isPresent ? 'Present' : 'Missing'; ?>
            </td>
        </tr>
        <?php endforeach; ?>
    </table>
    <h2>Raw HTTP Headers</h2>
    <pre><?php print_r($headers); ?></pre>
</body>
</html>
