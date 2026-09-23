<#
.SYNOPSIS
  Installs Omar's Claude Code setup on this machine: global CLAUDE.md, language
  servers, plugins, and the security-review model setting.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\setup.ps1            # full install
  powershell -ExecutionPolicy Bypass -File .\setup.ps1 -DryRun    # show what would happen

  Safe to re-run: existing settings are merged, not replaced, and an existing
  CLAUDE.md that differs is backed up before being overwritten.
#>
param(
  [switch]$DryRun,
  [switch]$SkipClaudeMd,
  [switch]$SkipPlugins,
  [string]$SecurityReviewModel = "claude-sonnet-5"
)

$ErrorActionPreference = "Stop"
$Repo = $PSScriptRoot
$ClaudeDir = Join-Path $env:USERPROFILE ".claude"
$Results = New-Object System.Collections.Generic.List[string]

function Step($msg) { Write-Host "`n== $msg" -ForegroundColor Cyan }
function Note($status, $msg) {
  $color = @{ OK = "Green"; SKIP = "DarkGray"; WARN = "Yellow"; FAIL = "Red"; PLAN = "Magenta" }[$status]
  Write-Host ("  [{0}] {1}" -f $status, $msg) -ForegroundColor $color
  $Results.Add("[$status] $msg")
}
function Has($cmd) { [bool](Get-Command $cmd -ErrorAction SilentlyContinue) }
function WriteUtf8NoBom($path, $text) {
  [System.IO.File]::WriteAllText($path, $text, (New-Object System.Text.UTF8Encoding($false)))
}

Step "Prerequisites"
$missing = @()
foreach ($c in "claude", "node", "npm", "git") { if (Has $c) { Note OK "$c found" } else { Note FAIL "$c not found"; $missing += $c } }
if (Has "python") { Note OK "python found" } elseif (Has "py") { Note OK "py launcher found" } else { Note WARN "python not found (needed for security-guidance and the skill scanner)" }
if ($missing) { Write-Host "`nInstall the missing tools above, then re-run." -ForegroundColor Red; exit 1 }
if (-not (Test-Path $ClaudeDir)) { New-Item -ItemType Directory -Path $ClaudeDir | Out-Null }

Step "Global CLAUDE.md"
$src = Join-Path $Repo "claude\CLAUDE.md"
$dst = Join-Path $ClaudeDir "CLAUDE.md"
if ($SkipClaudeMd) { Note SKIP "CLAUDE.md (-SkipClaudeMd)" }
elseif ((Test-Path $dst) -and ((Get-FileHash $dst).Hash -eq (Get-FileHash $src).Hash)) { Note SKIP "CLAUDE.md already up to date" }
elseif ($DryRun) { Note PLAN "would copy CLAUDE.md to $dst (backing up any existing, non-empty file)" }
else {
  if ((Test-Path $dst) -and (Get-Item $dst).Length -gt 0) {
    $bak = "$dst.bak-" + (Get-Date -Format "yyyyMMdd-HHmmss")
    Copy-Item $dst $bak
    Note WARN "existing CLAUDE.md backed up to $bak; merge anything you want to keep"
  }
  Copy-Item $src $dst -Force
  Note OK "CLAUDE.md installed"
}

Step "Language servers (npm, global)"
$servers = @{ "pyright" = "pyright"; "typescript-language-server" = "typescript-language-server"; "tsc" = "typescript" }
$toInstall = @($servers.Keys | Where-Object { -not (Has $_) } | ForEach-Object { $servers[$_] }) | Select-Object -Unique
if (-not $toInstall) { Note SKIP "pyright, typescript-language-server, typescript already installed" }
elseif ($DryRun) { Note PLAN ("would run: npm install -g " + ($toInstall -join " ")) }
else {
  & npm install -g @toInstall
  if ($LASTEXITCODE -eq 0) { Note OK ("installed " + ($toInstall -join ", ")) }
  else { Note FAIL "npm install failed (a company npm registry or proxy may be required)" }
}

Step "Plugins (claude-plugins-official)"
$plugins = Get-Content (Join-Path $Repo "claude\plugins.txt") | Where-Object { $_ -and -not $_.StartsWith("#") } | ForEach-Object { $_.Trim() }
if ($SkipPlugins) { Note SKIP "plugins (-SkipPlugins)" }
else {
  $installed = (& claude plugin list 2>&1 | Out-String)
  foreach ($p in $plugins) {
    $id = "$p@claude-plugins-official"
    if ($installed -match [regex]::Escape($id)) { Note SKIP "$p already installed"; continue }
    if ($DryRun) { Note PLAN "would install $id"; continue }
    $out = (& claude plugin install $id 2>&1 | Out-String)
    if ($LASTEXITCODE -eq 0 -and $out -match "Successfully installed") { Note OK "$p installed" }
    else { Note FAIL ("$p not installed; may be blocked by managed settings. Output: " + ($out.Trim() -split "`n")[-1]) }
  }
}

Step "settings.json (merge)"
$settingsPath = Join-Path $ClaudeDir "settings.json"
$settings = if (Test-Path $settingsPath) { Get-Content $settingsPath -Raw | ConvertFrom-Json } else { New-Object PSObject }
if (-not $settings.PSObject.Properties["env"]) { $settings | Add-Member -NotePropertyName env -NotePropertyValue (New-Object PSObject) }
$changed = $false
foreach ($k in "SECURITY_REVIEW_MODEL", "SG_AGENTIC_MODEL") {
  $cur = $settings.env.PSObject.Properties[$k]
  if ($cur -and $cur.Value -eq $SecurityReviewModel) { continue }
  if ($cur) { $cur.Value = $SecurityReviewModel } else { $settings.env | Add-Member -NotePropertyName $k -NotePropertyValue $SecurityReviewModel }
  $changed = $true
}
if (-not $changed) { Note SKIP "security review model already $SecurityReviewModel" }
elseif ($DryRun) { Note PLAN "would set SECURITY_REVIEW_MODEL / SG_AGENTIC_MODEL = $SecurityReviewModel" }
else {
  if (Test-Path $settingsPath) { Copy-Item $settingsPath "$settingsPath.bak-$(Get-Date -Format yyyyMMdd-HHmmss)" }
  WriteUtf8NoBom $settingsPath ($settings | ConvertTo-Json -Depth 20)
  Note OK "security review model set to $SecurityReviewModel (previous settings backed up)"
}

Step "Skill scanner self-test"
$py = if (Has "python") { "python" } elseif (Has "py") { "py" } else { $null }
if (-not $py) { Note SKIP "python not available" }
elseif ($DryRun) { Note PLAN "would run tests\test_scanner.py" }
else {
  & $py (Join-Path $Repo "tests\test_scanner.py")
  if ($LASTEXITCODE -eq 0) { Note OK "scanner tests passed" } else { Note FAIL "scanner tests failed" }
}

Step "Summary"
$Results | ForEach-Object { Write-Host "  $_" }
Write-Host "`nRestart any open Claude Code sessions to load the plugins and CLAUDE.md." -ForegroundColor Cyan
if ($Results -match "^\[FAIL\]") { exit 1 }
