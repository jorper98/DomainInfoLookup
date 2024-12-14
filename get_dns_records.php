<?php
// get_dns_records.php

// Prevent any HTML output from error messages
ini_set('display_errors', 0);
error_reporting(E_ALL);

// Ensure we're sending JSON response
header('Content-Type: application/json');

// Custom error handler to catch all errors
function errorHandler($errno, $errstr, $errfile, $errline) {
    echo json_encode([
        'error' => 'PHP Error: ' . $errstr,
        'debug' => [
            'file' => basename($errfile),
            'line' => $errline
        ]
    ]);
    exit;
}
set_error_handler('errorHandler');

// Function to safely sanitize string input
function sanitizeInput($input) {
    return htmlspecialchars(strip_tags(trim($input)), ENT_QUOTES, 'UTF-8');
}

// Function to safely get DNS records
function getDNSRecords($domain) {
    try {
        if (empty($domain)) {
            return ['error' => 'Domain name is required'];
        }

        // Validate domain format
        if (!preg_match('/^[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$/', $domain)) {
            return ['error' => 'Invalid domain format'];
        }

        $records = [];
        $types = [
            DNS_A => 'A',
            DNS_AAAA => 'AAAA',
            DNS_CNAME => 'CNAME',
            DNS_MX => 'MX',
            DNS_NS => 'NS',
            DNS_TXT => 'TXT'
        ];

        foreach ($types as $type_const => $type_name) {
            $result = @dns_get_record($domain, $type_const);
            
            if ($result) {
                foreach ($result as $record) {
                    $value = '';
                    switch ($type_name) {
                        case 'A':
                            $value = $record['ip'] ?? '';
                            break;
                        case 'AAAA':
                            $value = $record['ipv6'] ?? '';
                            break;
                        case 'CNAME':
                        case 'NS':
                            $value = $record['target'] ?? '';
                            break;
                        case 'MX':
                            $value = ($record['target'] ?? '') . 
                                    (isset($record['pri']) ? ' (Priority: ' . $record['pri'] . ')' : '');
                            break;
                        case 'TXT':
                            $value = $record['txt'] ?? '';
                            if (is_array($value)) {
                                $value = implode(', ', $value);
                            }
                            break;
                    }

                    if (!empty($value)) {
                        $records[] = [
                            'type' => $type_name,
                            'host' => $record['host'] ?? $domain,
                            'value' => $value,
                            'ttl' => $record['ttl'] ?? 0
                        ];
                    }
                }
            }
        }

        if (empty($records)) {
            return ['error' => 'No DNS records found for ' . $domain];
        }

        return $records;
    } catch (Exception $e) {
        return ['error' => 'Error processing request: ' . $e->getMessage()];
    }
}

// Main execution
try {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        echo json_encode(['error' => 'Only POST requests are allowed']);
        exit;
    }

    if (empty($_POST['domain'])) {
        echo json_encode(['error' => 'Domain parameter is required']);
        exit;
    }

    // Use modern sanitization approach instead of deprecated FILTER_SANITIZE_STRING
    $domain = sanitizeInput($_POST['domain']);
    $result = getDNSRecords($domain);
    
    echo json_encode($result);

} catch (Exception $e) {
    echo json_encode(['error' => 'Server error: ' . $e->getMessage()]);
}
?>