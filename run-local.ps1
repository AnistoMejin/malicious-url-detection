<#
    Malicious URL Detection - one-line setup WITHOUT Docker.

    Run with:
        irm https://raw.githubusercontent.com/AnistoMejin/malicious-url-detection/main/run-local.ps1 | iex

    Needs only git and Python 3.10+. Clones into C:\Project\malicious-url-detection,
    creates a virtual environment, installs packages, downloads the dataset,
    trains the model, then starts the app and prints the URL.
#>

param(
    [string]$Root = 'C:\Project',
    [int]$Port = 5000
)

$ErrorActionPreference = 'Stop'

$RepoUrl = 'https://github.com/AnistoMejin/malicious-url-detection.git'
$Dir     = Join-Path $Root 'malicious-url-detection'
$DataUrl = 'https://www.kaggle.com/api/v1/datasets/download/sid321axn/malicious-urls-dataset'

function Step($m) { Write-Host "`n=== $m ===" -ForegroundColor Cyan }
function Fail($m) { Write-Host "`nERROR: $m" -ForegroundColor Red; exit 1 }

# --- prerequisites -----------------------------------------------------
Step 'Checking prerequisites'
if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Fail 'git is not installed. Get it from https://git-scm.com/download/win'
}
$pyCmd = Get-Command python -ErrorAction SilentlyContinue
if (-not $pyCmd) { $pyCmd = Get-Command python3 -ErrorAction SilentlyContinue }
if (-not $pyCmd) {
    Fail 'Python is not installed. Get 3.10+ from https://www.python.org/downloads/ and tick "Add python.exe to PATH".'
}
Write-Host ("git and {0} are available" -f (& $pyCmd.Source --version))

# --- clone or update ---------------------------------------------------
Step "Fetching the project into $Dir"
if (-not (Test-Path $Root)) { New-Item -ItemType Directory -Force $Root | Out-Null }
if (Test-Path (Join-Path $Dir '.git')) {
    Write-Host 'Already cloned - pulling the latest changes'
    git -C $Dir pull --ff-only
} else {
    if (Test-Path $Dir) { Fail "$Dir exists but is not a git clone. Move or delete it, then re-run." }
    git clone --depth 1 $RepoUrl $Dir
}
Set-Location $Dir

# --- virtual environment ----------------------------------------------
# Call .venv\Scripts\python.exe directly rather than Activate.ps1, which the
# PowerShell execution policy often blocks.
$venvPy = Join-Path $Dir '.venv\Scripts\python.exe'
if (-not (Test-Path $venvPy)) {
    Step 'Creating the virtual environment'
    & $pyCmd.Source -m venv (Join-Path $Dir '.venv')
} else {
    Write-Host 'Virtual environment already exists - reusing it'
}

Step 'Installing packages (1-3 minutes)'
& $venvPy -m pip install --quiet --upgrade pip
& $venvPy -m pip install --quiet -r (Join-Path $Dir 'requirements.txt')
if ($LASTEXITCODE -ne 0) { Fail 'pip install failed - see the output above.' }
Write-Host 'Packages installed'

# --- dataset -----------------------------------------------------------
# The 44 MB CSV is gitignored, so a clone alone cannot train or run.
$csv = Join-Path $Dir 'data\malicious_phish.csv'
if ((Test-Path $csv) -and ((Get-Item $csv).Length -gt 40MB)) {
    Write-Host "`nDataset already present - skipping download"
} else {
    Step 'Downloading the dataset (44 MB)'
    New-Item -ItemType Directory -Force (Join-Path $Dir 'data') | Out-Null
    $zip = Join-Path $Dir 'data\kaggle.zip'
    Invoke-WebRequest -Uri $DataUrl -OutFile $zip
    Expand-Archive $zip -DestinationPath (Join-Path $Dir 'data') -Force
    Remove-Item $zip
    if (-not (Test-Path $csv)) { Fail 'Dataset download did not produce data\malicious_phish.csv' }
    Write-Host ("Dataset ready ({0:N0} MB)" -f ((Get-Item $csv).Length / 1MB))
}

# --- train -------------------------------------------------------------
$model = Join-Path $Dir 'model_cache\model.joblib'
if (Test-Path $model) {
    Write-Host "`nTrained model already present - skipping training"
} else {
    Step 'Training the model (2-4 minutes)'
    Write-Host 'This is the slow step. It is working even when it looks idle.' -ForegroundColor Yellow
    & $venvPy (Join-Path $Dir 'train.py')
    if ($LASTEXITCODE -ne 0) { Fail 'Training failed - see the output above.' }
}

# --- run ---------------------------------------------------------------
Step 'Starting the web application'
$env:PORT = "$Port"
$env:FLASK_DEBUG = '0'
Start-Process -FilePath $venvPy -ArgumentList (Join-Path $Dir 'app.py') -WorkingDirectory $Dir

$url = "http://localhost:$Port"
$ok = $false
foreach ($i in 1..30) {
    Start-Sleep -Seconds 2
    try {
        if ((Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 5).StatusCode -eq 200) { $ok = $true; break }
    } catch { }
}

if ($ok) {
    Write-Host "`n========================================================" -ForegroundColor Green
    Write-Host '  Malicious URL Detection is running' -ForegroundColor Green
    Write-Host "  URL: $url" -ForegroundColor Green
    Write-Host '========================================================' -ForegroundColor Green
    Write-Host "`n  Try:  github.com                 -> Benign"
    Write-Host '        104.211.28.157/powerpc     -> Malicious'
    Write-Host "`n  The app runs in a separate window. Close that window to stop it.`n"
    Start-Process $url
} else {
    Write-Host "`nThe app did not answer on $url." -ForegroundColor Yellow
    Write-Host "Start it manually to see the error:" -ForegroundColor Yellow
    Write-Host "  cd $Dir; .venv\Scripts\python.exe app.py`n"
}
