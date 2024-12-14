<?php 

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $domains = explode("\n", $_POST["domains"]);
    $show_ping = isset($_POST["show_ping"]);
    echo "<table class='bordered-table'><tr><th>Domain</th><th>IP Address</th>";
    if ($show_ping) {
        echo "<th>Ping Response Time (ms)</th>";
    }
    echo "<th>DNS Name Server</th></tr>";
    foreach ($domains as $domain) {
        $dns_ns = dns_get_record(trim($domain), DNS_NS)[0]['target'];
        $ip = gethostbyname(trim($domain));
        $ping_time = "";
        if ($show_ping) {
            $ping_time = exec("ping -c 1 $domain | awk -F 'time=' '{print $2}' | awk -F ' ' '{print $1}'");
        }
        echo "<tr><td>$domain</td><td>$ip</td>";
        if ($show_ping) {
            echo "<td>$ping_time</td>";
        }
        echo "<td>$dns_ns</td></tr>";
    }
    echo "</table>";
}
?>

<style>
    .bordered-table {
        border-collapse: collapse;
        border: 1px solid black;
        font-size: small;
    }

    .bordered-table th, .bordered-table td {
        border: 1px solid black;
        padding-left: 5px;
        padding-top: 5px;
        padding-bottom: 5px;
    }

    .bordered-table th:nth-child(2), .bordered-table td:nth-child(2) {
        text-align: right;
        padding-top: 5px;
        padding-bottom: 5px;
        padding-right: 5px;
    }

    .bordered-table tr:nth-child(even) {
        background-color: #f2f2f2;
    }
</style>

<form method="post">
    <label for="domains">Enter a list of domain names:</label><br>
    <textarea id="domains" name="domains" rows="4" cols="50"></textarea><br>
    <input type="checkbox" id="show_ping" name="show_ping" value="true">
    <label for="show_ping">Show ping response time</label><br>
    <input type="submit" value="Submit">
</form>
