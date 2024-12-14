<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SSL Certificate Expiration Checker</title>
    <style>
        table {
            border-collapse: collapse;
            width: 100%;
        }
        th, td {
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }
        th {
            background-color: #f2f2f2;
        }
    </style>
    
     <script>
        function viewLogFile() {
            window.open("ssl-domain-checks.txt", "_blank", "width=600,height=400");
        }
        
          
        function exportToCSV() {
            let csvContent = "data:text/csv;charset=utf-8,";
            csvContent += "Domain,Valid From,Valid To,Issuer Information\n";

            let rows = document.querySelectorAll("table tbody tr");
            rows.forEach(row => {
                let rowData = [];
                row.querySelectorAll("td").forEach(cell => {
                    rowData.push(cell.innerText);
                });
                csvContent += rowData.join(",") + "\n";
            });

            let encodedUri = encodeURI(csvContent);
            let link = document.createElement("a");
            link.setAttribute("href", encodedUri);
            link.setAttribute("download", "ssl_certificate_results.csv");
            document.body.appendChild(link);
            link.click();
        }
    </script>
    
    
</head>
<body>
    <h1>SSL Certificate Expiration Checker</h1>
    <form method="post" action="">
        <label for="domains">Enter domains (one per line):</label><br>
        <textarea id="domains" name="domains" rows="5" cols="50" required></textarea><br>
        <input type="submit" value="Check SSL Certificates">
    </form>

    <?php
    if ($_SERVER["REQUEST_METHOD"] == "POST") {
        $domainsInput = $_POST["domains"];
        $domains = preg_split("/\r\n|\n|\r/", $domainsInput); // Split input by new lines
        
        
        // Log user information and entered domains to a file
        $logData = date("Y-m-d H:i:s") . " | IP: " . $_SERVER['REMOTE_ADDR'] . "\n";
        $logData .= "Domains:\n" . $domainsInput . "\n\n";
        file_put_contents("ssl-domain-checks.txt", $logData, FILE_APPEND);


        echo "<table>";
        echo "<thead>";
        echo "<tr>";
        echo "<th>Domain</th>";
        echo "<th>Valid From</th>";
        echo "<th>Valid To</th>";
        echo "<th>Issuer Information</th>";
        echo "</tr>";
        echo "</thead>";
        echo "<tbody>";

        foreach ($domains as $domain) {
            $domain = trim($domain); // Remove any leading/trailing whitespaces
            $url = "https://$domain";
            $orignal_parse = parse_url($url, PHP_URL_HOST);
            $get = stream_context_create(["ssl" => ["capture_peer_cert" => true]]);
            $read = stream_socket_client("ssl://" . $orignal_parse . ":443", $errno, $errstr, 30, STREAM_CLIENT_CONNECT, $get);

            if ($read) {
                $cert = stream_context_get_params($read);
                $certinfo = openssl_x509_parse($cert['options']['ssl']['peer_certificate']);

                $validFrom = date(DATE_RFC2822, $certinfo['validFrom_time_t']);
                $validTo = date(DATE_RFC2822, $certinfo['validTo_time_t']);
                $issuerInfo = $certinfo['issuer']['CN']; // Extract issuer common name

                echo "<tr>";
                echo "<td>$domain</td>";
                echo "<td>$validFrom</td>";
                echo "<td>$validTo</td>";
                echo "<td>$issuerInfo</td>";
                echo "</tr>";
            } else {
                echo "<tr>";
                echo "<td>$domain</td>";
                echo "<td colspan='3'>Error connecting</td>";
                echo "</tr>";
            }
        }

        echo "</tbody>";
        echo "</table>";
    }
    ?>
      <button onclick="viewLogFile()">View Log File</button>
      <button onclick="exportToCSV()">Export to CSV</button>
</body>
</html>
