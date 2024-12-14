<?php
/**
 * Ping Handler Script
 * Performs ping operations for the Domain Information Tool
 */

// Enable error reporting for debugging
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Set headers
header('Content-Type: application/json');

// Function to safely execute ping command
function pingDomain($domain) {
    // Validate domain
    if (!filter_var($domain, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
        return json_encode(['error' => 'Invalid domain name']);
    }

    // Log the incoming domain for debugging
    error_log("Attempting to ping domain: " . $domain);

    // Sanitize domain for command line usage
    $domain = escapeshellarg($domain);
    
    // Detect operating system
    $isWindows = strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';
    
    if ($isWindows) {
        $cmd = "ping -n 1 -w 1000 $domain";
    } else {
        // Modified Linux command to be more explicit
        $cmd = "ping -c 1 -W 2 $domain";
    }

    // Log the command being executed
    error_log("Executing command: " . $cmd);

    try {
        // Execute ping command
        $output = shell_exec($cmd);
        
        // Log the raw output
        error_log("Raw ping output: " . print_r($output, true));

        if ($output === null) {
            error_log("shell_exec returned null");
            return json_encode("Command execution failed");
        }

        // For Linux systems
        if (!$isWindows) {
            // Try different patterns
            if (preg_match('/time=([0-9.]+)\s*ms/', $output, $matches)) {
                $ping_time = round(floatval($matches[1]), 2);
                return json_encode($ping_time . ' ms');
            }
            if (preg_match('/min\/avg\/max(?:\/mdev)?\s*=\s*([0-9.]+)\/([0-9.]+)\/([0-9.]+)/', $output, $matches)) {
                $ping_time = round(floatval($matches[2]), 2);
                return json_encode($ping_time . ' ms');
            }
        } 
        // For Windows systems
        else {
            if (preg_match('/Average\s*=\s*(\d+)ms/', $output, $matches)) {
                return json_encode($matches[1] . ' ms');
            }
            if (preg_match('/time[=<]([0-9]+)ms/', $output, $matches)) {
                return json_encode($matches[1] . ' ms');
            }
        }

        // If we reached here, we couldn't parse the output
        // Let's return the actual output for debugging
        $cleaned_output = preg_replace('/[\r\n]+/', ' ', $output);
        return json_encode("Raw ping output: " . substr($cleaned_output, 0, 100));

    } catch (Exception $e) {
        error_log("Exception in ping execution: " . $e->getMessage());
        return json_encode("Error: " . $e->getMessage());
    }
}

// Main execution
try {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        http_response_code(405);
        die(json_encode("Method not allowed"));
    }

    if (!isset($_POST['domain'])) {
        http_response_code(400);
        die(json_encode("Missing domain parameter"));
    }

    $domain = trim($_POST['domain']);
    error_log("Received request for domain: " . $domain);
    
    echo pingDomain($domain);

} catch (Exception $e) {
    error_log("Main execution error: " . $e->getMessage());
    http_response_code(500);
    echo json_encode("Server error: " . $e->getMessage());
}
?>