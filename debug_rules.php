<?php
/**
 * Rules Bot Debug Log Viewer
 * Temporary debug tool - allows viewing logs to diagnose connection issues.
 */
$logFile = 'debug_rules_bot.log';

echo "<html><head><title>Rules Bot Debug</title>";
echo "<style>
    body { background: #0f172a; color: #e2e8f0; font-family: monospace; padding: 20px; }
    h1 { color: #3b82f6; border-bottom: 1px solid #1e293b; padding-bottom: 10px; }
    .log-container { background: #1e293b; padding: 15px; border-radius: 8px; white-space: pre-wrap; word-wrap: break-word; border: 1px solid #334155; max-height: 80vh; overflow-y: auto; }
    .refresh-btn { background: #3b82f6; color: white; border: none; padding: 10px 20px; border-radius: 6px; cursor: pointer; margin-bottom: 20px; font-weight: bold; }
    .refresh-btn:hover { background: #2563eb; }
    .empty { color: #94a3b8; font-style: italic; }
    .timestamp { color: #64748b; margin-right: 10px; }
</style></head><body>";

echo "<h1>Rules Bot Live Debug Logs</h1>";
echo "<button class='refresh-btn' onclick='location.reload()'>Refresh Logs</button>";

if (file_exists($logFile)) {
    $content = file_get_contents($logFile);
    if (empty($content)) {
        echo "<div class='log-container'><span class='empty'>Log file is empty. Bot may not be producing output yet.</span></div>";
    } else {
        echo "<div class='log-container'>" . htmlspecialchars($content) . "</div>";
    }
} else {
    echo "<div class='log-container'><span class='empty'>Log file '$logFile' not found. Bot might not be running or hasn't started logging yet.</span></div>";
}

echo "</body></html>";
