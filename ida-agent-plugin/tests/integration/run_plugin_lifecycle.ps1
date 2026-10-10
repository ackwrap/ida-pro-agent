[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$IdaDir,

    [Parameter(Mandatory = $true)]
    [string]$PluginPath,

    [Parameter(Mandatory = $true)]
    [string]$PythonExecutable,

    [int]$TimeoutSeconds = 120,

    [switch]$KeepArtifacts
)

$ErrorActionPreference = "Stop"

$idaExecutable = Join-Path $IdaDir "idat.exe"
$driverScript = Join-Path $PSScriptRoot "ida_bridge_hold.py"
$verifierScript = Join-Path $PSScriptRoot "verify_plugin_rpc.py"

foreach ($requiredPath in @($idaExecutable, $PluginPath, $PythonExecutable, $driverScript, $verifierScript)) {
    if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
        throw "Required file does not exist: $requiredPath"
    }
}

$testRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("ida-agent-plugin-lifecycle-" + [guid]::NewGuid().ToString("N"))
$idaUserDir = Join-Path $testRoot "ida-user"
$pluginDir = Join-Path $idaUserDir "plugins"
$instanceDir = Join-Path $testRoot "instances"
$releaseFile = Join-Path $testRoot "release"
$readyFile = Join-Path $testRoot "ready"
$registryEvidence = Join-Path $testRoot "registry-evidence.json"
$logPath = Join-Path $testRoot "ida.log"
$databasePath = Join-Path $testRoot "lifecycle.i64"
$testSucceeded = $false
$idaProcess = $null

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
    $startInfo.Environment["IDA_AGENT_TEST_HOLD_SECONDS"] = [string]$TimeoutSeconds
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
            $instanceFiles = [System.IO.Directory]::GetFiles($instanceDir, "*.json")
            if ($instanceFiles.Count -gt 1) {
                throw "IDA published more than one instance registry entry"
            }
            if ($instanceFiles.Count -eq 1) {
                $instanceFile = $instanceFiles[0]
            }
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
        throw "IDA did not publish the stable RPC fixture"
    }
    [System.IO.File]::Copy($instanceFile, $registryEvidence, $true)
    $descriptor = [System.IO.File]::ReadAllText($registryEvidence) | ConvertFrom-Json

    $verifierInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $verifierInfo.FileName = $PythonExecutable
    $verifierInfo.WorkingDirectory = $testRoot
    $verifierInfo.UseShellExecute = $false
    $verifierInfo.CreateNoWindow = $true
    $verifierInfo.RedirectStandardOutput = $true
    $verifierInfo.RedirectStandardError = $true
    foreach ($argument in @(
        $verifierScript,
        "--instance-file", $registryEvidence,
        "--fixture-file", $readyFile
    )) {
        $verifierInfo.ArgumentList.Add($argument)
    }
    $verifierProcess = [System.Diagnostics.Process]::new()
    $verifierProcess.StartInfo = $verifierInfo
    if (-not $verifierProcess.Start()) {
        throw "Failed to start Plugin RPC verifier"
    }
    $verifierOutput = $verifierProcess.StandardOutput.ReadToEndAsync()
    $verifierError = $verifierProcess.StandardError.ReadToEndAsync()
    $remainingMilliseconds = [Math]::Max(1, [int]($deadline - [DateTime]::UtcNow).TotalMilliseconds)
    if (-not $verifierProcess.WaitForExit($remainingMilliseconds)) {
        $verifierProcess.Kill($true)
        $verifierProcess.WaitForExit()
        throw "Plugin RPC verifier timed out"
    }
    $verifierText = $verifierOutput.GetAwaiter().GetResult()
    $verifierErrorText = $verifierError.GetAwaiter().GetResult()
    if ($verifierProcess.ExitCode -ne 0) {
        [System.IO.File]::WriteAllText($releaseFile, "release")
        if (-not $idaProcess.HasExited) {
            $idaProcess.WaitForExit(5000) | Out-Null
        }
        $idaDiagnostics = ""
        if (Test-Path -LiteralPath $logPath -PathType Leaf) {
            try {
                $idaDiagnostics = [System.IO.File]::ReadAllText($logPath)
            }
            catch {
                $idaDiagnostics = "IDA log remained unavailable: $($_.Exception.Message)"
            }
        }
        throw "Plugin RPC verifier failed: $verifierErrorText`nIDA diagnostics:`n$idaDiagnostics"
    }
    if (-not $verifierText.Contains("pluginRpcCoverage=")) {
        throw "Plugin RPC verifier did not report method coverage"
    }
    $verifierText.Trim()

    [System.IO.File]::WriteAllText($releaseFile, "release")
    $remainingMilliseconds = [Math]::Max(1, [int]($deadline - [DateTime]::UtcNow).TotalMilliseconds)
    if (-not $idaProcess.WaitForExit($remainingMilliseconds)) {
        $idaProcess.Kill($true)
        $idaProcess.WaitForExit()
        throw "IDA lifecycle test timed out after $TimeoutSeconds seconds"
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
        "[ida-agent-test] lifecycle passed",
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
    "IDA plugin lifecycle test passed"
}
finally {
    if ($null -ne $idaProcess -and -not $idaProcess.HasExited) {
        [System.IO.File]::WriteAllText($releaseFile, "release")
        if (-not $idaProcess.WaitForExit(5000)) {
            $idaProcess.Kill($true)
            $idaProcess.WaitForExit()
        }
    }
    if ($testSucceeded -and -not $KeepArtifacts) {
        Remove-Item -LiteralPath $testRoot -Recurse -Force
    }
    elseif (Test-Path -LiteralPath $testRoot) {
        "IDA plugin lifecycle artifacts: $testRoot"
    }
}
