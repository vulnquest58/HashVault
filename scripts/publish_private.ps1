<#
.SYNOPSIS
    Publish HashVault to GitHub as a PRIVATE repository.

.DESCRIPTION
    Creates the repository explicitly with --private, commits the tree and
    pushes. Refuses to run if anything sensitive or oversized would ship, and
    refuses to continue if gh is missing or unauthenticated.

.EXAMPLE
    pwsh -File scripts/publish_private.ps1
    pwsh -File scripts/publish_private.ps1 -DryRun
#>
[CmdletBinding()]
param(
    [string]$Owner = "vulnquest58",
    [string]$Repo  = "HashVault",
    [string]$Message = "Initial commit: HashVault security auditing toolkit",
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $root

function Fail($msg) { Write-Host "ERROR: $msg" -ForegroundColor Red; exit 1 }
function Step($msg) { Write-Host "== $msg" -ForegroundColor Cyan }

# 1. Required tooling ---------------------------------------------------------
Step "Checking tooling"
foreach ($tool in @("git", "gh")) {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        Fail "$tool is not installed or not on PATH."
    }
}
git --version
gh --version | Select-Object -First 1

Step "Checking GitHub authentication"
gh auth status
if ($LASTEXITCODE -ne 0) { Fail "gh is not authenticated. Run: gh auth login" }

# 2. Safety gate: nothing sensitive or oversized ------------------------------
Step "Auditing the working tree"
$blocked = @()
$blocked += Get-ChildItem -Recurse -File -Filter *.sqlite3 -ErrorAction SilentlyContinue
$blocked += Get-ChildItem -Recurse -File -Filter *.db      -ErrorAction SilentlyContinue
$blocked += Get-ChildItem -Recurse -File -Filter *.pot     -ErrorAction SilentlyContinue
$blocked += Get-ChildItem -Path sessions -Recurse -File    -ErrorAction SilentlyContinue

$oversize = Get-ChildItem -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object { $_.Length -gt 95MB -and $_.FullName -notmatch '\\sessions\\' }

if ($blocked.Count -gt 0) {
    Write-Host "Refusing to publish: state files present." -ForegroundColor Yellow
    $blocked | Select-Object -First 10 FullName | Format-Table -AutoSize
    Fail "Move or delete these first (they are gitignored, but verify)."
}
if ($oversize.Count -gt 0) {
    Write-Host "Refusing to publish: files over 95MB." -ForegroundColor Yellow
    $oversize | Select-Object Length, FullName | Format-Table -AutoSize
    Fail "GitHub rejects blobs over 100MB."
}
Write-Host "Tree looks clean." -ForegroundColor Green

if ($DryRun) {
    Write-Host "`nDry run complete; no repository was created." -ForegroundColor Yellow
    exit 0
}

# 3. Initialise ---------------------------------------------------------------
Step "Initialising repository"
if (-not (Test-Path .git)) { git init | Out-Null }
git symbolic-ref HEAD refs/heads/main
git add -A
git -c user.name="$Owner" -c user.email="$Owner@users.noreply.github.com" commit -m "$Message"

# 4. Create PRIVATE repo and push --------------------------------------------
Step "Creating PRIVATE repository $Owner/$Repo"
gh repo create "$Owner/$Repo" --private --source . --remote origin --push

if ($LASTEXITCODE -ne 0) { Fail "Repository creation or push failed." }

Step "Confirming visibility"
$visibility = gh repo view "$Owner/$Repo" --json visibility --jq .visibility
Write-Host "Visibility: $visibility" -ForegroundColor Green
if ($visibility -ne "PRIVATE") {
    Fail "Repository is $visibility, expected PRIVATE. Review it immediately."
}

Write-Host "`nPublished: https://github.com/$Owner/$Repo (private)" -ForegroundColor Green
