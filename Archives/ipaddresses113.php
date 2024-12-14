<?php
/**
 * AppName: Domain Info Lookup Tool
 * Description: PHP Script to return IP Addresses and SSL Certificate information from a list of domain names.
 * Version: 1.1.3
 * Author: Jorge Pereira
 */

// Function to extract metadata from doc block
function getMetadata() {
    $docBlock = [];
    $pattern = '/\* (AppName|Version|Author|Description):\s*(.+)/';
    $lines = file(__FILE__);
    
    foreach ($lines as $line) {
        if (preg_match($pattern, $line, $matches)) {
            $docBlock[strtolower($matches[1])] = trim($matches[2]);
        }
    }
    
    return $docBlock;
}
function getRegistrarInfo($domain) {
    try {
        $whois_server = 'whois.internic.net';
        $port = 43;
        
        $sock = fsockopen($whois_server, $port, $errno, $errstr, 30);
        if (!$sock) {
            return "Unable to connect to WHOIS server";
        }
        
        fputs($sock, $domain . "\r\n");
        $response = '';
        
        while (!feof($sock)) {
            $response .= fgets($sock, 128);
        }
        fclose($sock);
        
        // First check for domain registration
        if (preg_match('/Registrar:\s*(.+)$/mi', $response, $matches)) {
            return trim($matches[1]);
        }
        
        // Then check for availability using common patterns
        $notFoundPatterns = [
            'No match for domain',
            'NOT FOUND',
            'No entries found',
            'Domain not found',
            'No match for "',
            'Status: AVAILABLE',
            'Domain Status: free',
            'No Data Found'
        ];
        
        foreach ($notFoundPatterns as $pattern) {
            if (stripos($response, $pattern) !== false) {
                return "Domain Available";
            }
        }
        
        // Check for referral to another WHOIS server
        if (preg_match('/Whois Server:\s*(.+)$/mi', $response, $matches)) {
            $secondary_whois = trim($matches[1]);
            $sock = fsockopen($secondary_whois, $port, $errno, $errstr, 30);
            if ($sock) {
                fputs($sock, $domain . "\r\n");
                $secondary_response = '';
                while (!feof($sock)) {
                    $secondary_response .= fgets($sock, 128);
                }
                fclose($sock);
                
                // Check for registrar in secondary response
                if (preg_match('/Registrar:\s*(.+)$/mi', $secondary_response, $matches)) {
                    return trim($matches[1]);
                }
                
                // Check for availability patterns in secondary response
                foreach ($notFoundPatterns as $pattern) {
                    if (stripos($secondary_response, $pattern) !== false) {
                        return "Domain Available";
                    }
                }
            }
        }
        
        // If domain name pattern is found but no registrar info
        if (preg_match('/Domain Name:\s*' . preg_quote($domain, '/') . '/i', $response)) {
            return "Registered (Registrar Unknown)";
        }
        
        // Default to checking if response seems to indicate availability
        if (empty(trim($response)) || 
            stripos($response, 'error') !== false || 
            stripos($response, $domain) === false) {
            return "Domain Available";
        }
        
        return "Status Unknown";
    } catch (Exception $e) {
        return "Error checking domain status";
    }
}

// Function to get SSL certificate expiration
function getSSLCertificateInfo($domain) {
    try {
        $context = stream_context_create([
            "ssl" => [
                "capture_peer_cert" => true,
                "verify_peer" => false,
                "verify_peer_name" => false,
            ]
        ]);

        $client = stream_socket_client(
            "ssl://$domain:443",
            $errno,
            $errstr,
            30,
            STREAM_CLIENT_CONNECT,
            $context
        );

        if (!$client) {
            return "Unable to connect";
        }

        $params = stream_context_get_params($client);
        
        if (!empty($params["options"]["ssl"]["peer_certificate"])) {
            $cert = openssl_x509_parse($params["options"]["ssl"]["peer_certificate"]);
            $certExpiryDate = date('Y-m-d', $cert['validTo_time_t']);
            $daysUntilExpiry = ceil(($cert['validTo_time_t'] - time()) / (60 * 60 * 24));
            
            return [
                'expiry_date' => $certExpiryDate,
                'days_remaining' => $daysUntilExpiry,
                'issuer' => $cert['issuer']['O'] ?? 'Unknown'
            ];
        }
        
        return "No certificate found";
    } catch (Exception $e) {
        return "Error: " . $e->getMessage();
    }
}

// Get metadata once at the start
$metadata = getMetadata();

// Security headers
header("Content-Security-Policy: default-src 'self'; script-src 'self' https://ajax.googleapis.com 'unsafe-inline'; style-src 'self' 'unsafe-inline'");
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo htmlspecialchars($metadata['appname'] ?? 'Domain Information Tool'); ?></title>
    <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.6.4/jquery.min.js"></script>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 20px;
            padding: 20px;
        }
        .bordered-table {
            border-collapse: collapse;
            width: 100%;
            margin-top: 20px;
            box-shadow: 0 0 20px rgba(0, 0, 0, 0.1);
        }
        .bordered-table th, .bordered-table td {
            border: 2px solid #ddd;
            padding: 12px;
            text-align: left;
        }
        .bordered-table th {
            background-color: #f4f4f4;
            border-bottom: 3px solid #ddd;
            color: #333;
            font-weight: bold;
        }
        .bordered-table tr:hover {
            background-color: #f8f8f8;
        }
        .bordered-table tr:nth-child(even) {
            background-color: #f9f9f9;
        }
        .ping-status {
            color: #666;
            font-style: italic;
        }
        footer {
            margin-top: 30px;
            padding-top: 10px;
            border-top: 1px solid #ddd;
            text-align: center;
            font-size: 0.9em;
            color: #666;
        }
        textarea {
            width: 100%;
            max-width: 500px;
            padding: 10px;
            border: 2px solid #ddd;
            border-radius: 4px;
            margin-bottom: 10px;
        }
        input[type="submit"] {
            padding: 10px 20px;
            background-color: #4CAF50;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            margin-top: 10px;
        }
        input[type="submit"]:hover {
            background-color: #45a049;
        }
        /* New SSL certificate styles */
        .ssl-warning {
            color: #ff6b6b;
            font-weight: bold;
        }
        .ssl-ok {
            color: #4CAF50;
            font-weight: bold;
        }
        .ssl-expiring {
            color: #ffa500;
            font-weight: bold;
        }
        .checkbox-group {
            margin: 10px 0;
        }
        .checkbox-group label {
            margin-right: 20px;
        }
        input[type="checkbox"] {
            margin-right: 5px;
        }
		
		        /* Add new styles for available domain links */
        .available-domain {
            color: #2196F3;
            text-decoration: none;
            cursor: pointer;
        }
        
        .available-domain:hover {
            text-decoration: underline;
            color: #0D47A1;
        }
        
        /* Add an icon next to available domains */
        .available-domain::after {
            content: " 🔗";
            font-size: 0.9em;
        }
		
		
		 /* Modal styles */
        .modal {
            display: none;
            position: fixed;
            z-index: 1;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            overflow: auto;
            background-color: rgba(0,0,0,0.4);
        }

		.modal-content {
			background-color: #fefefe;
			margin: 15% auto;
			padding: 20px;
			border: 1px solid #888;
			width: 95%; /* Changed from 80% to 95% */
			max-width: 1200px; /* Changed from 600px to 1200px */
			border-radius: 5px;
			box-shadow: 0 4px 8px rgba(0,0,0,0.1);
		}

        .dns-link {
            color: #2196F3;
            text-decoration: underline;
            cursor: pointer;
        }

        .dns-link:hover {
            color: #0D47A1;
        }

        .close {
            color: #aaa;
            float: right;
            font-size: 28px;
            font-weight: bold;
            cursor: pointer;
        }

        .close:hover,
        .close:focus {
            color: black;
            text-decoration: none;
        }

        .dns-records-table {
            width: 100%;
            margin-top: 10px;
            border-collapse: collapse;
        }

        .dns-records-table th,
        .dns-records-table td {
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }

        .dns-records-table th {
            background-color: #f4f4f4;
        }

        .modal-title {
            margin-top: 0;
            color: #333;
        }
		
    </style>
</head>
<body>
    <h1><?php echo htmlspecialchars($metadata['appname'] ?? 'Domain Information Tool'); ?></h1>
    <p><?php echo htmlspecialchars($metadata['description'] ?? ''); ?></p>

 <form method="post">
        <label for="domains">Enter a list of domain names (one per line):</label><br>
        <textarea id="domains" name="domains" rows="4" cols="50" required></textarea><br>
        <div class="checkbox-group">
            <input type="checkbox" id="show_ping" name="show_ping" value="true">
            <label for="show_ping">Show ping response time</label>
            <input type="checkbox" id="show_ssl" name="show_ssl" value="true">
            <label for="show_ssl">Show SSL certificate info</label>
        </div>
        <input type="submit" value="Submit">
    </form>

    <?php 
    if ($_SERVER["REQUEST_METHOD"] == "POST") {
        $domains = array_filter(array_map('trim', explode("\n", $_POST["domains"] ?? '')));
        $show_ping = isset($_POST["show_ping"]);
        $show_ssl = isset($_POST["show_ssl"]);

        if (!empty($domains)) {
            echo "<table class='bordered-table'>";
            echo "<tr><th>Domain</th><th>IP Address</th>";
            if ($show_ping) {
                echo "<th>Ping Response Time (ms)</th>";
            }
            if ($show_ssl) {
                echo "<th>SSL Certificate Expiration</th>";
            }
            echo "<th>Registrar</th><th>DNS Name Server</th></tr>";

 
foreach ($domains as $domain) {
    if (filter_var($domain, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
        try {
            $dns_records = dns_get_record($domain, DNS_NS);
            $dns_ns = !empty($dns_records) ? $dns_records[0]['target'] : 'N/A';
            $ip = gethostbyname($domain);
            $registrar = getRegistrarInfo($domain);
            
            echo "<tr>";
            
            // Domain cell
            if ($registrar !== "Domain Available" && $registrar !== "Status Unknown" && $registrar !== "Unable to connect to WHOIS server") {
                echo "<td><a href='https://" . htmlspecialchars($domain) . 
                     "' target='_blank' class='registered-domain'>" . 
                     htmlspecialchars($domain) . "</a></td>";
            } else {
                echo "<td>" . htmlspecialchars($domain) . "</td>";
            }
            
            echo "<td>" . htmlspecialchars($ip) . "</td>";
            
            // Ping Response column
            if ($show_ping) {
                if ($registrar === "Domain Available") {
                    echo "<td>N/A</td>";
                } else {
                    $domain_id = md5($domain);
                    echo "<td><span id='domain_$domain_id' class='ping-status'>Pending...</span></td>";
                    echo "<script>
                        $(document).ready(function() {
                            $.ajax({
                                url: 'ping.php',
                                type: 'POST',
                                data: { domain: '" . addslashes($domain) . "' },
                                success: function(response) {
                                    try {
                                        if (typeof response === 'string') {
                                            response = JSON.parse(response);
                                        }
                                        $('#domain_" . $domain_id . "')
                                            .text(response.error ? response.error : response)
                                            .css('color', response.error ? '#ff0000' : '#000000');
                                    } catch(e) {
                                        $('#domain_" . $domain_id . "')
                                            .text(response)
                                            .css('color', '#000000');
                                    }
                                },
                                error: function(xhr, status, error) {
                                    $('#domain_" . $domain_id . "')
                                        .text('Ping failed: ' + error)
                                        .css('color', '#ff0000');
                                }
                            });
                        });
                    </script>";
                }
            }

            // SSL Certificate column
            if ($show_ssl) {
                if ($registrar === "Domain Available") {
                    echo "<td>N/A</td>";
                } else {
                    $ssl_info = getSSLCertificateInfo($domain);
                    echo "<td>";
                    if (is_array($ssl_info)) {
                        $class = 'ssl-ok';
                        if ($ssl_info['days_remaining'] < 0) {
                            $class = 'ssl-warning';
                        } elseif ($ssl_info['days_remaining'] < 30) {
                            $class = 'ssl-expiring';
                        }
                        echo "<span class='$class'>";
                        echo "Expires: " . htmlspecialchars($ssl_info['expiry_date']) . "<br>";
                        echo "Days remaining: " . htmlspecialchars($ssl_info['days_remaining']) . "<br>";
                        echo "Issuer: " . htmlspecialchars($ssl_info['issuer']);
                        echo "</span>";
                    } else {
                        echo "<span class='ssl-warning'>" . htmlspecialchars($ssl_info) . "</span>";
                    }
                    echo "</td>";
                }
            }
            
            echo "<td>" . htmlspecialchars($registrar) . "</td>";
            
            // DNS Name Server column - Modified to show N/A without link for available domains
            if ($registrar === "Domain Available") {
                echo "<td>N/A</td>";
            } else {
                echo "<td><a class='dns-link' onclick='getDnsRecords(\"" . addslashes($domain) . "\")'>" . 
                     htmlspecialchars($dns_ns) . "</a></td>";
            }
            
            echo "</tr>";
            
        } catch (Exception $e) {
            echo "<tr>";
            echo "<td>" . htmlspecialchars($domain) . "</td>";
            $colspan = 3;
            if ($show_ping) $colspan++;
            if ($show_ssl) $colspan++;
            echo "<td colspan='$colspan'>Error processing domain</td>";
            echo "</tr>";
        }
    } else {
        echo "<tr>";
        echo "<td>" . htmlspecialchars($domain) . "</td>";
        $colspan = 3;
        if ($show_ping) $colspan++;
        if ($show_ssl) $colspan++;
        echo "<td colspan='$colspan'>Invalid domain name</td>";
        echo "</tr>";
    }
}
            
            echo "</table>";
        }
    }
	    ?>
	

    <footer>
        <p>
            <?php echo htmlspecialchars($metadata['appname'] ?? 'Domain Information Tool'); ?> |
            Version: <?php echo htmlspecialchars($metadata['version'] ?? '1.0.0'); ?> |
            Author: <?php echo htmlspecialchars($metadata['author'] ?? 'Unknown'); ?> |
            &copy; <?php echo date('Y'); ?>
        </p>
    </footer>
	 <!-- Modal for DNS Records -->
    <div id="dnsModal" class="modal">
        <div class="modal-content">
            <span class="close">&times;</span>
            <h3 class="modal-title">DNS Records</h3>
            <div id="dnsRecords"></div>
        </div>
    </div>
	
	
	<script>
    // All functions and code must be either inside functions or in the global scope
    // but return statements can only be inside functions
    
    // Utility function for escaping HTML
    function escapeHtml(unsafe) {
        // Handle null/undefined
        if (unsafe === null || unsafe === undefined) {
            return '';
        }
        // Convert to string
        unsafe = unsafe.toString();
        
        return unsafe
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    // Modal element references
    var modal = document.getElementById("dnsModal");
    var span = document.getElementsByClassName("close")[0];

    // Modal event handlers
    span.onclick = function() {
        modal.style.display = "none";
    }

    window.onclick = function(event) {
        if (event.target == modal) {
            modal.style.display = "none";
        }
    }

    // DNS records function
    function getDnsRecords(domain) {
        document.getElementById('dnsRecords').innerHTML = 'Loading...';
        modal.style.display = "block";
        
        $.ajax({
            url: 'get_dns_records.php',
            type: 'POST',
            data: { domain: domain },
            dataType: 'json',
            success: function(response) {
                console.log('Response:', response);
                
                if (response.error) {
                    document.getElementById('dnsRecords').innerHTML = 
                        `<div style="color: red; padding: 10px;">${escapeHtml(response.error)}</div>`;
                    return;
                }
                
                let html = '<table class="dns-records-table">';
                html += '<tr><th>Type</th><th>Host</th><th>Value</th><th>TTL</th></tr>';
                
                response.forEach(record => {
                    const type = record.type || '';
                    const host = record.host || '';
                    const value = record.value || '';
                    const ttl = record.ttl || '0';
                    
                    html += `<tr>
                        <td>${escapeHtml(type)}</td>
                        <td>${escapeHtml(host)}</td>
                        <td>${escapeHtml(value)}</td>
                        <td>${escapeHtml(ttl)}</td>
                    </tr>`;
                });
                
                html += '</table>';
                document.getElementById('dnsRecords').innerHTML = html;
            },
            error: function(xhr, status, error) {
                console.error('Ajax error:', {xhr, status, error});
                let errorMessage = 'Error loading DNS records';
                try {
                    const response = xhr.responseText;
                    if (response) {
                        errorMessage += ': ' + response;
                    }
                } catch (e) {
                    errorMessage += ': ' + error;
                }
                document.getElementById('dnsRecords').innerHTML = 
                    `<div style="color: red; padding: 10px;">${escapeHtml(errorMessage)}</div>`;
            }
        });
    }
</script>
	
</body>
</html>