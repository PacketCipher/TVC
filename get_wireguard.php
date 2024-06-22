<?php
// Enable error reporting
ini_set("display_errors", 1);
ini_set("display_startup_errors", 1);
error_reporting(E_ERROR | E_PARSE);

// Include the functions file
require "functions.php";

// Fetch the JSON data from the API and decode it into an associative array
$sourcesArray = json_decode(
    file_get_contents("channels_wireguard.json"),
    true
);

// Function to process a batch of sources
function processBatch($batchSources, $sourcesArray, &$configsList)
{
    // Initialize cURL multi handle
    $multiHandle = curl_multi_init();
    $curlHandles = [];

    // Add individual cURL handles to the multi handle
    foreach ($batchSources as $source) {
        $url = "https://t.me/s/" . $source;
        $curlHandle = curl_init($url);
        curl_setopt($curlHandle, CURLOPT_RETURNTRANSFER, true);
        $curlHandles[$source] = $curlHandle;
        curl_multi_add_handle($multiHandle, $curlHandle);
    }

    // Execute the multi handle
    $running = null;
    do {
        curl_multi_exec($multiHandle, $running);
        curl_multi_select($multiHandle);
    } while ($running);

    // Get the content from the individual cURL handles
    foreach ($curlHandles as $source => $curlHandle) {
        $tempData = curl_multi_getcontent($curlHandle);
        $type = implode("|", $sourcesArray[$source]);
        $tempExtract = extractLinksByType($tempData, $type);
        if (!is_null($tempExtract)) {
            $configsList[$source] = $tempExtract;
        }
        curl_multi_remove_handle($multiHandle, $curlHandle);
        curl_close($curlHandle);
    }

    // Close the multi handle
    curl_multi_close($multiHandle);
}

// Batch size
$batchSize = 10;
$totalSources = count($sourcesArray);
$sourceKeys = array_keys($sourcesArray);
$configsList = [];
echo "Fetching Configs\n";

// Process the sources in batches
for ($i = 0; $i < $totalSources; $i += $batchSize) {
    $batchSources = array_slice($sourceKeys, $i, min($batchSize, $totalSources - $i));
    processBatch($batchSources, $sourcesArray, $configsList);
    echo "\rProgress: " . round(($i + count($batchSources)) / $totalSources * 100) . "% \n";
}

echo "\nProcessing Configs\n";
$finalOutput = [];
$needleArray = ["&amp", ";"];
$replaceArray = ["", "&"];

$Counter = 1;
foreach ($configsList as $source => $configs) {
    foreach (array_reverse($configs) as $key => $config) {
        array_push(
            $finalOutput,
            str_replace(
                $needleArray,
                $replaceArray,
                $config . "|" . $Counter
            )
        );
        $Counter++;
    }
}

$finalOutput = implode("\n", $finalOutput);
$finalOutput_With_Header = hiddifyHeader("TVC | MIX") . $finalOutput;

if (!empty($finalOutput)) {
    file_put_contents("config_wireguard.txt", $finalOutput);
    file_put_contents("subscriptions/xray/normal/wireguard", $finalOutput_With_Header);
    echo "\nConfig file written successfully.\n";
} else {
    echo "\nNo valid new configurations found. Config file not written.\n";
}

echo "\nGetting Configs Done!\n";
