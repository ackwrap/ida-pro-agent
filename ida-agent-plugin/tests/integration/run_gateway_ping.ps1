[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$IdaDir,

    [Parameter(Mandatory = $true)]
    [string]$PluginPath,

    [Parameter(Mandatory = $true)]
    [string]$GatewayDir,

    [Parameter(Mandatory = $true)]
    [string]$GoExecutable,

    [int]$TimeoutSeconds = 120,

    [switch]$KeepArtifacts
)

$ErrorActionPreference = "Stop"

function Stop-ProcessTreeAndWait {
    param(
        [System.Diagnostics.Process]$Process,
        [string]$Name
    )
    if ($null -eq $Process) {
        return $true
    }
    try {
        if ($Process.HasExited) {
            return $true
        }
        $Process.Kill($true)
        if ($Process.WaitForExit(5000)) {
            return $true
        }
        Write-Warning "$Name process tree did not exit within the cleanup timeout"
    }
    catch {
        Write-Warning "$Name process tree cleanup failed: $($_.Exception.Message)"
    }
    return $false
}

$idaExecutable = Join-Path $IdaDir "idat.exe"
$driverScript = Join-Path $PSScriptRoot "ida_bridge_hold.py"
$gatewayModule = Join-Path $GatewayDir "go.mod"
foreach ($requiredPath in @($idaExecutable, $PluginPath, $driverScript, $GoExecutable, $gatewayModule)) {
    if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
        throw "Required file does not exist: $requiredPath"
    }
}

$testRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("ida-mcp-ping-" + [guid]::NewGuid().ToString("N"))
$idaUserDir = Join-Path $testRoot "ida-user"
$pluginDir = Join-Path $idaUserDir "plugins"
$instanceDir = Join-Path $testRoot "instances"
$releaseFile = Join-Path $testRoot "release"
$readyFile = Join-Path $testRoot "ready"
$logPath = Join-Path $testRoot "ida.log"
$registryEvidence = Join-Path $testRoot "registry-evidence.json"
$databasePath = Join-Path $testRoot "gateway-ping.i64"
$testSucceeded = $false
$serveConfirmed = $false
$idaProcess = $null
$pingProcess = $null
$mcpProcess = $null
$buildProcess = $null
$stdioProcess = $null

try {
    [System.IO.Directory]::CreateDirectory($pluginDir) | Out-Null
    $isolatedPlugin = Join-Path $pluginDir ([System.IO.Path]::GetFileName($PluginPath))
    [System.IO.File]::Copy($PluginPath, $isolatedPlugin, $true)

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $idaExecutable
    $startInfo.WorkingDirectory = $testRoot
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.Environment["IDAUSR"] = $idaUserDir
    $startInfo.Environment["IDA_AGENT_INSTANCE_DIR"] = $instanceDir
    $startInfo.Environment["IDA_AGENT_TEST_RELEASE_FILE"] = $releaseFile
    $startInfo.Environment["IDA_AGENT_TEST_READY_FILE"] = $readyFile
    $startInfo.Environment["IDA_AGENT_TEST_DIAGNOSTICS"] = "1"
    foreach ($argument in @(
        "-A",
        "-c",
        "-L$logPath",
        "-o$databasePath",
        "-S$driverScript",
        $PluginPath
    )) {
        $startInfo.ArgumentList.Add($argument)
    }

    $idaProcess = [System.Diagnostics.Process]::new()
    $idaProcess.StartInfo = $startInfo
    if (-not $idaProcess.Start()) {
        throw "Failed to start IDA"
    }
    $standardOutput = $idaProcess.StandardOutput.ReadToEndAsync()
    $standardError = $idaProcess.StandardError.ReadToEndAsync()

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $instanceFile = $null
    $bridgeReady = $false
    while ([DateTime]::UtcNow -lt $deadline -and -not $idaProcess.HasExited) {
        if (Test-Path -LiteralPath $instanceDir -PathType Container) {
            $instanceFile = [System.IO.Directory]::GetFiles($instanceDir, "*.json") | Select-Object -First 1
        }
        $bridgeReady = Test-Path -LiteralPath $readyFile -PathType Leaf
        if ($null -ne $instanceFile -and $bridgeReady) {
            break
        }
        Start-Sleep -Milliseconds 50
    }
    if ($null -eq $instanceFile) {
        throw "IDA did not publish an instance registry entry"
    }
    if (-not $bridgeReady) {
        throw "IDA did not become ready for database reads"
    }
    [System.IO.File]::Copy($instanceFile, $registryEvidence, $true)
    $descriptor = [System.IO.File]::ReadAllText($registryEvidence) | ConvertFrom-Json
    $readyInfo = [System.IO.File]::ReadAllText($readyFile) | ConvertFrom-Json
    $functionAddress = [string]$readyInfo.functionAddress
    $nonFunctionAddress = [string]$readyInfo.nonFunctionAddress
    $xrefAddress = [string]$readyInfo.xrefAddress
    $memoryBytes = [string]$readyInfo.memoryBytes
    $stringAddress = [string]$readyInfo.stringAddress
    $stringValue = [string]$readyInfo.stringValue
    $stackFrameAddress = [string]$readyInfo.stackFrameAddress
    $uninitializedAddress = [string]$readyInfo.uninitializedAddress
    $segmentLastAddress = [string]$readyInfo.segmentLastAddress
    $boundsFunctionAddress = [string]$readyInfo.boundsFunctionAddress
    $boundsExtendedEnd = [string]$readyInfo.boundsExtendedEnd
    $tailStart = [string]$readyInfo.tailStart
    $tailEnd = [string]$readyInfo.tailEnd
    if ($functionAddress -notmatch '^0x[0-9A-Fa-f]{1,16}$') {
        throw "IDA did not publish a valid function address"
    }
    if ($nonFunctionAddress -notmatch '^0x[0-9A-Fa-f]{1,16}$') {
        throw "IDA did not publish a valid non-function address"
    }
    if ($xrefAddress -notmatch '^0x[0-9A-Fa-f]{1,16}$') {
        throw "IDA did not publish a valid xref address"
    }
    if ($memoryBytes -notmatch '^[0-9a-f]{16}$') {
        throw "IDA did not publish valid memory bytes"
    }
    if ($stringAddress -notmatch '^0x[0-9A-Fa-f]{1,16}$' -or [string]::IsNullOrEmpty($stringValue)) {
        throw "IDA did not publish valid string test data"
    }
    if ($uninitializedAddress -notmatch '^0x[0-9A-Fa-f]{1,16}$' -or $segmentLastAddress -notmatch '^0x[0-9A-Fa-f]{1,16}$') {
        throw "IDA did not publish valid memory error test addresses"
    }
    foreach ($mutationAddress in @($boundsFunctionAddress, $boundsExtendedEnd, $tailStart, $tailEnd)) {
        if ($mutationAddress -notmatch '^0x[0-9A-Fa-f]{1,16}$') {
            throw "IDA did not publish valid function mutation addresses"
        }
    }

    $pingInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $pingInfo.FileName = $GoExecutable
    $pingInfo.WorkingDirectory = $GatewayDir
    $pingInfo.UseShellExecute = $false
    $pingInfo.CreateNoWindow = $true
    $pingInfo.RedirectStandardOutput = $true
    $pingInfo.RedirectStandardError = $true
    foreach ($argument in @("run", "./cmd/ida-agent-rpc-ping", "-instance-dir", $instanceDir, "-timeout", "30s", "-database-info", "-function-address", $functionAddress, "-verify-function-errors", "-non-function-address", $nonFunctionAddress, "-verify-function-search", "-xref-address", $xrefAddress, "-memory-bytes", $memoryBytes, "-string-address", $stringAddress, "-string-value", $stringValue, "-uninitialized-address", $uninitializedAddress, "-segment-last-address", $segmentLastAddress, "-verify-decompiler")) {
        $pingInfo.ArgumentList.Add($argument)
    }
    $pingProcess = [System.Diagnostics.Process]::new()
    $pingProcess.StartInfo = $pingInfo
    if (-not $pingProcess.Start()) {
        throw "Failed to start Go RPC ping"
    }
    $pingOutput = $pingProcess.StandardOutput.ReadToEndAsync()
    $pingError = $pingProcess.StandardError.ReadToEndAsync()
    if (-not $pingProcess.WaitForExit(30000)) {
        if (-not (Stop-ProcessTreeAndWait $pingProcess "Go RPC ping")) {
            throw "Go RPC ping timed out and its process tree could not be stopped"
        }
        throw "Go RPC ping timed out"
    }
    if ($pingProcess.ExitCode -ne 0) {
        throw "Go RPC ping failed: $($pingError.GetAwaiter().GetResult())"
    }
    $pingText = $pingOutput.GetAwaiter().GetResult()
    if (-not $pingText.Contains("instance=")) {
        throw "Go RPC ping did not report a handshaken instance"
    }
    if (-not $pingText.Contains("databaseInfo=")) {
        throw "Go RPC client did not report database.info"
    }
    if (-not $pingText.Contains("functionInfo=")) {
        throw "Go RPC client did not report function.get"
    }
    if (-not $pingText.Contains("functionErrors=ok")) {
        throw "Go RPC client did not verify function.get errors"
    }
    if (-not $pingText.Contains("functionSearch=ok")) {
        throw "Go RPC client did not verify function.search pagination"
    }
    if (-not $pingText.Contains("xrefQuery=ok")) {
        throw "Go RPC client did not verify xref.query pagination"
    }
    if (-not $pingText.Contains("memoryRead=ok")) {
        throw "Go RPC client did not verify memory.read formats"
    }
    if (-not $pingText.Contains("functionDecompile=ok")) {
        throw "Go RPC client did not verify function.decompile"
    }
    $decompilerCapability = [regex]::Match($pingText, 'functionDecompile=ok capability=(true|false)').Value
    if ($decompilerCapability -ne "functionDecompile=ok capability=true") {
        throw "IDA Hex-Rays successful decompile coverage was not established"
    }

    $mcpInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $mcpInfo.FileName = $GoExecutable
    $mcpInfo.WorkingDirectory = $GatewayDir
    $mcpInfo.UseShellExecute = $false
    $mcpInfo.CreateNoWindow = $true
    $mcpInfo.RedirectStandardOutput = $true
    $mcpInfo.RedirectStandardError = $true
    foreach ($argument in @("run", "./cmd/ida-agent-mcp-ping", "-instance-dir", $instanceDir, "-timeout", "90s", "-function-address", $functionAddress, "-non-function-address", $nonFunctionAddress, "-bounds-function-address", $boundsFunctionAddress, "-bounds-extended-end", $boundsExtendedEnd, "-tail-start", $tailStart, "-tail-end", $tailEnd, "-xref-address", $xrefAddress, "-memory-bytes", $memoryBytes, "-string-address", $stringAddress, "-string-value", $stringValue, "-stack-frame-address", $stackFrameAddress)) {
        $mcpInfo.ArgumentList.Add($argument)
    }
    $mcpProcess = [System.Diagnostics.Process]::new()
    $mcpProcess.StartInfo = $mcpInfo
    if (-not $mcpProcess.Start()) {
        throw "Failed to start MCP Tool integration client"
    }
    $mcpOutput = $mcpProcess.StandardOutput.ReadToEndAsync()
    $mcpError = $mcpProcess.StandardError.ReadToEndAsync()
    if (-not $mcpProcess.WaitForExit(120000)) {
        if (-not (Stop-ProcessTreeAndWait $mcpProcess "HTTP MCP integration client")) {
            throw "HTTP MCP integration client timed out and its process tree could not be stopped"
        }
        throw "MCP Tool integration client timed out"
    }
    if ($mcpProcess.ExitCode -ne 0) {
        throw "MCP Tool integration client failed: $($mcpError.GetAwaiter().GetResult())"
    }
    $mcpText = $mcpOutput.GetAwaiter().GetResult()
    if (-not $mcpText.Contains("mcpDomains=ok callableMethods=98 transport=http")) {
        throw "HTTP MCP integration client did not verify all domain methods"
    }
    if (-not $mcpText.Contains("databaseMutations=ok")) {
        throw "HTTP MCP integration client did not verify database mutations"
    }

    $gatewayExecutable = Join-Path $testRoot "ida-mcp.exe"
    $buildInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $buildInfo.FileName = $GoExecutable
    $buildInfo.WorkingDirectory = $GatewayDir
    $buildInfo.UseShellExecute = $false
    $buildInfo.CreateNoWindow = $true
    $buildInfo.RedirectStandardOutput = $true
    $buildInfo.RedirectStandardError = $true
    foreach ($argument in @("build", "-o", $gatewayExecutable, ".")) {
        $buildInfo.ArgumentList.Add($argument)
    }
    $buildProcess = [System.Diagnostics.Process]::new()
    $buildProcess.StartInfo = $buildInfo
    if (-not $buildProcess.Start()) {
        throw "Failed to build the Gateway executable"
    }
    $buildOutput = $buildProcess.StandardOutput.ReadToEndAsync()
    $buildError = $buildProcess.StandardError.ReadToEndAsync()
    if (-not $buildProcess.WaitForExit(120000)) {
        if (-not (Stop-ProcessTreeAndWait $buildProcess "Gateway build")) {
            throw "Gateway build timed out and its process tree could not be stopped"
        }
        throw "Gateway build timed out"
    }
    if ($buildProcess.ExitCode -ne 0) {
        throw "Gateway build failed: $($buildError.GetAwaiter().GetResult())"
    }
    $buildOutput.GetAwaiter().GetResult() | Out-Null

    $stdioInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $stdioInfo.FileName = $GoExecutable
    $stdioInfo.WorkingDirectory = $GatewayDir
    $stdioInfo.UseShellExecute = $false
    $stdioInfo.CreateNoWindow = $true
    $stdioInfo.RedirectStandardOutput = $true
    $stdioInfo.RedirectStandardError = $true
    foreach ($argument in @("run", "./cmd/ida-agent-mcp-ping", "-instance-dir", $instanceDir, "-gateway-executable", $gatewayExecutable, "-timeout", "90s", "-function-address", $functionAddress, "-non-function-address", $nonFunctionAddress, "-bounds-function-address", $boundsFunctionAddress, "-bounds-extended-end", $boundsExtendedEnd, "-tail-start", $tailStart, "-tail-end", $tailEnd, "-xref-address", $xrefAddress, "-memory-bytes", $memoryBytes, "-string-address", $stringAddress, "-string-value", $stringValue, "-stack-frame-address", $stackFrameAddress)) {
        $stdioInfo.ArgumentList.Add($argument)
    }
    $stdioProcess = [System.Diagnostics.Process]::new()
    $stdioProcess.StartInfo = $stdioInfo
    if (-not $stdioProcess.Start()) {
        throw "Failed to start the stdio MCP integration client"
    }
    $stdioOutput = $stdioProcess.StandardOutput.ReadToEndAsync()
    $stdioError = $stdioProcess.StandardError.ReadToEndAsync()
    if (-not $stdioProcess.WaitForExit(120000)) {
        if (-not (Stop-ProcessTreeAndWait $stdioProcess "stdio MCP integration client")) {
            throw "stdio MCP integration client timed out and its process tree could not be stopped"
        }
        throw "stdio MCP integration client timed out"
    }
    if ($stdioProcess.ExitCode -ne 0) {
        throw "stdio MCP integration client failed: $($stdioError.GetAwaiter().GetResult())"
    }
    $stdioText = $stdioOutput.GetAwaiter().GetResult()
    if (-not $stdioText.Contains("mcpDomains=ok callableMethods=98 transport=stdio")) {
        throw "stdio MCP integration client did not verify all domain methods"
    }
    if (-not $stdioText.Contains("databaseMutations=ok")) {
        throw "stdio MCP integration client did not verify database mutations"
    }
    $serveConfirmed = $true

    [System.IO.File]::WriteAllText($releaseFile, "release")
    if (-not $idaProcess.WaitForExit($TimeoutSeconds * 1000)) {
        if (-not (Stop-ProcessTreeAndWait $idaProcess "IDA")) {
            throw "IDA did not exit after RPC ping and its process tree could not be stopped"
        }
        throw "IDA did not exit after RPC ping"
    }
    $output = $standardOutput.GetAwaiter().GetResult() + $standardError.GetAwaiter().GetResult()
    if (Test-Path -LiteralPath $logPath -PathType Leaf) {
        $output += [System.IO.File]::ReadAllText($logPath)
    }
    if ($idaProcess.ExitCode -ne 0) {
        throw "IDA exited with code $($idaProcess.ExitCode); artifacts retained at $testRoot"
    }
    foreach ($marker in @(
        "[ida-agent] plugin loaded",
        "pipe=$([string]$descriptor.pipe)",
        "[ida-agent] plugin is active",
        "[ida-agent-test] bridge ready",
        "[ida-agent] plugin unloaded"
    )) {
        if (-not $output.Contains($marker)) {
            throw "IDA output did not contain '$marker'; artifacts retained at $testRoot"
        }
    }
    if (Test-Path -LiteralPath $instanceFile) {
        throw "Instance registry entry was not removed during plugin shutdown"
    }

    $testSucceeded = $true
    "IDA RPC plus HTTP/stdio MCP integration passed ($decompilerCapability)"
}
finally {
    foreach ($child in @(
        @{ Process = $pingProcess; Name = "Go RPC ping" },
        @{ Process = $mcpProcess; Name = "HTTP MCP integration client" },
        @{ Process = $buildProcess; Name = "Gateway build" },
        @{ Process = $stdioProcess; Name = "stdio MCP integration client" }
    )) {
        if (-not (Stop-ProcessTreeAndWait $child.Process $child.Name)) {
            "Failed to stop $($child.Name) during cleanup"
        }
    }
    if ($null -ne $idaProcess -and -not $idaProcess.HasExited) {
        if ($serveConfirmed) {
            [System.IO.File]::WriteAllText($releaseFile, "release")
        }
        if (-not $serveConfirmed -or -not $idaProcess.WaitForExit(5000)) {
            if (-not (Stop-ProcessTreeAndWait $idaProcess "IDA")) {
                "Failed to stop IDA during cleanup"
            }
        }
    }
    if (Test-Path -LiteralPath $instanceDir -PathType Container) {
        foreach ($sensitiveFile in [System.IO.Directory]::GetFiles($instanceDir)) {
            [System.IO.File]::Delete($sensitiveFile)
        }
    }
    if ($testSucceeded -and -not $KeepArtifacts) {
        Remove-Item -LiteralPath $testRoot -Recurse -Force
    }
    elseif (Test-Path -LiteralPath $testRoot) {
        "IDA Gateway ping artifacts: $testRoot"
    }
}
