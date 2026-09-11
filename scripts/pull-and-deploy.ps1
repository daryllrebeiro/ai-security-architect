# ==============================================================================
# Pull and Deploy Orchestrator - AI Security Architect (PowerShell)
# Architecture Pattern: daryllrebeiro/support-master
# 100% Free-Tier and Zero-Cost Automated Delivery Engine
# ==============================================================================

[CmdletBinding(PositionalBinding = $false)]
param(
  [string]$ProjectId,
  [string]$Region,
  [string]$ServiceName,
  [switch]$DryRun,
  [switch]$LocalDocker,
  [int]$MinInstances = 0,
  [int]$MaxInstances = 2,
  [string]$Cpu = "1",
  [string]$Memory = "1Gi",
  [switch]$NoCpuThrottling,
  [string]$Ingress = "default",
  [Parameter(ValueFromRemainingArguments = $true)]
  $RemainingArgs
)

$ErrorActionPreference = "Stop"

function Write-LogHeader([string]$Title) {
  Write-Host ""
  Write-Host "================================================================================" -ForegroundColor Cyan
  Write-Host "  $Title" -ForegroundColor Cyan
  Write-Host "================================================================================" -ForegroundColor Cyan
}

function Write-LogStep([string]$Message) {
  Write-Host "[*] [STEP] $Message..." -ForegroundColor Yellow
}

function Write-LogSuccess([string]$Message) {
  Write-Host "[+] [SUCCESS] $Message" -ForegroundColor Green
}

function Write-LogError([string]$Message) {
  Write-Host "[!] [ERROR] $Message" -ForegroundColor Red
}

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = Split-Path -Parent $ScriptDir
Set-Location $RootDir

$StartTime = Get-Date
$StashCreated = $false
$StashTag = ""

Write-LogHeader "AI Security Architect - Pull and Deploy Pipeline (PowerShell)"

try {
  # ----------------------------------------------------------------------------
  # 1. Inspect Git Working Tree
  # ----------------------------------------------------------------------------
  Write-LogStep "Inspecting local git working tree"
  $GitStatus = git status --porcelain
  if ($GitStatus) {
    $StashTag = "pull-and-deploy-auto-stash-" + (Get-Date -Format 'yyyyMMddHHmmss')
    Write-Host "   Uncommitted changes detected. Creating temporary stash: $StashTag" -ForegroundColor Gray
    git stash push -u -m "$StashTag" | Out-Null
    $StashCreated = $true
    Write-LogSuccess "Working changes safely stashed ($StashTag)"
  } else {
    Write-Host "   Working tree clean. Proceeding directly." -ForegroundColor Gray
  }

  # ----------------------------------------------------------------------------
  # 2. Synchronize with Remote Branch (origin/main)
  # ----------------------------------------------------------------------------
  Write-LogStep "Pulling latest commits from origin/main"
  try {
    git pull origin main
    $CurrentSha = (git rev-parse --short HEAD).Trim()
    Write-LogSuccess "Repository synchronized to commit $CurrentSha"
  } catch {
    Write-LogError "Failed to pull from origin/main. Aborting deployment."
    if ($StashCreated) {
      Write-Host "   Restoring previously stashed working state..." -ForegroundColor Gray
      git stash pop | Out-Null
      $StashCreated = $false
    }
    exit 1
  }

  # ----------------------------------------------------------------------------
  # 3. Restore Stashed Changes (if applicable)
  # ----------------------------------------------------------------------------
  if ($StashCreated) {
    Write-LogStep "Restoring stashed changes ($StashTag)"
    try {
      git stash pop | Out-Null
      $StashCreated = $false
      Write-LogSuccess "Stashed changes reapplied cleanly"
    } catch {
      Write-LogError "Conflict detected while reapplying stash. Resolve conflicts before deploying."
      exit 1
    }
  }

  # ----------------------------------------------------------------------------
  # 4. Chain into Zero-Cost Deployment Engine
  # ----------------------------------------------------------------------------
  Write-LogStep "Handoff to zero-cost cloud deployment engine (scripts/deploy.ps1)"
  $DeployScript = Join-Path $ScriptDir "deploy.ps1"
  if (-not (Test-Path $DeployScript)) {
    Write-LogError "Deployment script not found at $DeployScript"
    exit 1
  }

  # Forward bound parameters to deploy.ps1
  & $DeployScript @PSBoundParameters

  $Duration = [math]::Round(((Get-Date) - $StartTime).TotalSeconds)
  Write-LogHeader "Pull and Deploy Complete in ${Duration}s"
} catch {
  Write-LogError "Pipeline failed: $_"
  if ($StashCreated) {
    Write-Host "Attempting emergency stash restoration..." -ForegroundColor Gray
    git stash pop 2>$null | Out-Null
    $StashCreated = $false
  }
  exit 1
}

