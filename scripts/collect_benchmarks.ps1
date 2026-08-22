# Collect every measurable claim in CHRONOS into one timestamped result set.
#
# Runs the test suite, the FHE scaling series, the VDF/Groth16 benchmarks, and
# the end-to-end demo, recording the machine specification alongside them so the
# numbers are citable. Each step is timed and its exit code recorded; a failing
# step is reported and the run continues, so one broken step never costs you the
# rest of the data.
#
# Invoked by run-benchmarks.bat. Can also be run directly:
#   powershell -ExecutionPolicy Bypass -File scripts\collect_benchmarks.ps1

[CmdletBinding()]
param(
    # Sequential-squaring count for the end-to-end demo.
    [int]$T = 500000,

    # Skip the FHE scaling series. It is the slowest step by a wide margin.
    [switch]$SkipFhe,

    # Skip the end-to-end demo (needs config/default.toml in the mission dir).
    [switch]$SkipDemo
)

$ErrorActionPreference = 'Continue'
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo

$stamp   = Get-Date -Format 'yyyy-MM-dd_HHmmss'
$outDir  = Join-Path $repo "benchmark-results\$stamp"
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

$results = [System.Collections.Generic.List[object]]::new()

function Write-Banner([string]$text) {
    Write-Host ''
    Write-Host ('=' * 74) -ForegroundColor DarkCyan
    Write-Host "  $text" -ForegroundColor Cyan
    Write-Host ('=' * 74) -ForegroundColor DarkCyan
}

# Run one step, tee its output to a file, record duration and exit code.
function Invoke-Step {
    param(
        [string]$Name,
        [string]$LogFile,
        [scriptblock]$Command
    )

    Write-Banner $Name
    $log = Join-Path $outDir $LogFile
    $sw  = [System.Diagnostics.Stopwatch]::StartNew()

    & $Command 2>&1 | Tee-Object -FilePath $log
    $code = $LASTEXITCODE
    $sw.Stop()

    $status = if ($code -eq 0) { 'PASS' } else { "FAIL (exit $code)" }
    $colour = if ($code -eq 0) { 'Green' } else { 'Red' }
    Write-Host ("-> {0} in {1:n1}s" -f $status, $sw.Elapsed.TotalSeconds) -ForegroundColor $colour

    $results.Add([pscustomobject]@{
        Step     = $Name
        Status   = $status
        Seconds  = [math]::Round($sw.Elapsed.TotalSeconds, 1)
        Log      = $LogFile
    })
}

# ── Machine specification ─────────────────────────────────────────────────────
# Without this the timings are not citable: a reader cannot compare against an
# unknown machine.
Write-Banner 'Recording machine specification'

$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
$ramGB = [math]::Round(
    ((Get-CimInstance Win32_PhysicalMemory | Measure-Object Capacity -Sum).Sum / 1GB), 1)
$os = Get-CimInstance Win32_OperatingSystem

$spec = [ordered]@{
    'Timestamp'        = (Get-Date -Format 'u')
    'CPU'              = $cpu.Name.Trim()
    'Physical cores'   = $cpu.NumberOfCores
    'Logical cores'    = $cpu.NumberOfLogicalProcessors
    'Max clock (MHz)'  = $cpu.MaxClockSpeed
    'RAM (GB)'         = $ramGB
    'OS'               = "$($os.Caption) $($os.Version)"
    'Power source'     = (Get-CimInstance Win32_Battery |
                            Select-Object -First 1 -ExpandProperty BatteryStatus |
                            ForEach-Object { if ($_ -eq 2) { 'AC (mains)' } else { 'Battery - timings may throttle' } })
    'rustc'            = (& rustc --version 2>&1 | Out-String).Trim()
    'cargo'            = (& cargo --version 2>&1 | Out-String).Trim()
    'git commit'       = (& git rev-parse --short HEAD 2>&1 | Out-String).Trim()
    'git branch'       = (& git rev-parse --abbrev-ref HEAD 2>&1 | Out-String).Trim()
    'git dirty'        = if ((& git status --porcelain 2>&1)) { 'yes - uncommitted changes present' } else { 'no' }
}

$specPath = Join-Path $outDir 'machine-spec.txt'
$spec.GetEnumerator() | ForEach-Object { "{0,-18} {1}" -f $_.Key, $_.Value } |
    Tee-Object -FilePath $specPath

if ($spec['Power source'] -like 'Battery*') {
    Write-Host ''
    Write-Host 'WARNING: running on battery. Plug in before trusting these timings.' -ForegroundColor Yellow
}
if ($spec['git dirty'] -like 'yes*') {
    Write-Host 'WARNING: working tree is dirty. Results may not match any commit.' -ForegroundColor Yellow
}

# ── Steps ─────────────────────────────────────────────────────────────────────

Invoke-Step -Name 'Full workspace test suite' -LogFile 'workspace-tests.txt' -Command {
    cargo test --workspace
}

Invoke-Step -Name 'chronos-core library tests' -LogFile 'core-tests.txt' -Command {
    cargo test -p chronos-core --lib
}

Invoke-Step -Name 'VDF and Groth16 benchmarks' -LogFile 'bench.txt' -Command {
    cargo run -p chronos-bench --release
}

if (-not $SkipFhe) {
    Invoke-Step -Name 'FHE scaling series (slow)' -LogFile 'fhe-scaling.txt' -Command {
        cargo test -p chronos-core --release -- --ignored test_mlp_scaling_series --nocapture
    }
} else {
    Write-Host 'Skipping FHE scaling series (-SkipFhe).' -ForegroundColor DarkGray
}

if (-not $SkipDemo) {
    # demo.ps1 sets $ErrorActionPreference = 'Stop'. Cargo writes its progress
    # ("Compiling serde_core ...") to stderr, and under Stop a native command's
    # stderr is promoted to a terminating error, so the demo aborted in ~1s while
    # still compiling. Running it in a child process isolates its preference from
    # ours and lets stderr stay what it is: progress output, not failure.
    Invoke-Step -Name "End-to-end demo (T=$T)" -LogFile 'demo.txt' -Command {
        $demo = Join-Path $PSScriptRoot 'demo.ps1'
        & powershell -NoProfile -ExecutionPolicy Bypass -File $demo -T $T -KeepArtifacts
    }
} else {
    Write-Host 'Skipping end-to-end demo (-SkipDemo).' -ForegroundColor DarkGray
}

# ── Extract the numbers that appear in the paper ───────────────────────────────
Write-Banner 'Extracting headline figures'

$patterns = @(
    @{ Label = 'R1CS constraints';   Regex = 'constraints?\D{0,20}(\d[\d,]*)' }
    @{ Label = 'Proof size (bytes)'; Regex = 'proof\D{0,20}(\d+)\s*bytes' }
    @{ Label = 'Verify time';        Regex = 'verif\w*\D{0,20}([\d.]+\s*[munµ]?s)' }
    @{ Label = 'Prove time';         Regex = 'prov\w*\D{0,20}([\d.]+\s*[munµ]?s)' }
    @{ Label = 'Setup time';         Regex = 'setup\D{0,20}([\d.]+\s*[munµ]?s)' }
    @{ Label = 'Squarings/sec';      Regex = '([\d,]+)\s*squarings?\s*/?\s*sec' }
    @{ Label = 'Abstract states';    Regex = '([\d,]+)\s*(?:abstract\s*)?states' }
    @{ Label = 'Tests passed';       Regex = '(\d+)\s+passed' }
)

$figures = [System.Collections.Generic.List[string]]::new()
foreach ($log in Get-ChildItem $outDir -Filter '*.txt') {
    if ($log.Name -eq 'machine-spec.txt') { continue }
    $text = Get-Content $log.FullName -Raw
    foreach ($p in $patterns) {
        foreach ($m in [regex]::Matches($text, $p.Regex, 'IgnoreCase')) {
            $figures.Add(("{0,-22} {1,-16} ({2})" -f $p.Label, $m.Groups[1].Value, $log.Name))
        }
    }
}

$figuresUnique = $figures | Sort-Object -Unique
if ($figuresUnique) {
    $figuresUnique | Tee-Object -FilePath (Join-Path $outDir 'headline-figures.txt')
} else {
    Write-Host 'No figures matched. Check the logs directly.' -ForegroundColor Yellow
}

# ── Summary ───────────────────────────────────────────────────────────────────
Write-Banner 'Summary'
$results | Format-Table -AutoSize | Out-String | Write-Host

$summary = @()
$summary += "# CHRONOS benchmark run - $stamp"
$summary += ''
$summary += '## Machine'
$summary += '```'
$summary += ($spec.GetEnumerator() | ForEach-Object { "{0,-18} {1}" -f $_.Key, $_.Value })
$summary += '```'
$summary += ''
$summary += '## Steps'
$summary += ''
$summary += '| Step | Status | Seconds | Log |'
$summary += '|---|---|---|---|'
foreach ($r in $results) {
    $summary += "| $($r.Step) | $($r.Status) | $($r.Seconds) | $($r.Log) |"
}
$summary += ''
$summary += '## Headline figures (regex-extracted - verify against logs before publishing)'
$summary += '```'
$summary += $figuresUnique
$summary += '```'

$summaryPath = Join-Path $outDir 'SUMMARY.md'
$summary | Set-Content -Path $summaryPath -Encoding UTF8

$failed = @($results | Where-Object { $_.Status -ne 'PASS' }).Count
Write-Host "Results written to: $outDir" -ForegroundColor Cyan
Write-Host "Summary:            $summaryPath" -ForegroundColor Cyan
Write-Host ''
if ($failed -eq 0) {
    Write-Host 'ALL STEPS PASSED' -ForegroundColor Green
} else {
    Write-Host "$failed STEP(S) FAILED - read the logs before using any numbers." -ForegroundColor Red
}
Write-Host ''
Write-Host 'Reminder: run the FHE series twice and confirm the numbers agree' -ForegroundColor DarkGray
Write-Host 'before putting them in the paper.' -ForegroundColor DarkGray
