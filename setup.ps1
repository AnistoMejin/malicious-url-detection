<#
    Malicious URL Detection - one-line Docker setup.

    Run with:
        irm https://raw.githubusercontent.com/AnistoMejin/malicious-url-detection/main/setup.ps1 | iex

    Clones the repo into C:\Project\malicious-url-detection, builds the Docker
    image (which downloads the dataset and trains the model), starts the
    container and prints the URL.
#>

$ErrorActionPreference = 'Stop'

$Root      = 'C:\Project'
$RepoUrl   = 'https://github.com/AnistoMejin/malicious-url-detection.git'
$Name      = 'malicious-url-detection'
$Dir       = Join-Path $Root $Name
$Image     = 'malicious-url-detection'
$Container = 'malicious-url-detection'
$Port      = 5000

function Step($m) { Write-Host "`n=== $m ===" -ForegroundColor Cyan }
function Fail($m) { Write-Host "`nERROR: $m" -ForegroundColor Red; exit 1 }

# --- prerequisites -----------------------------------------------------
Step 'Checking prerequisites'

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Fail "git is not installed. Get it from https://git-scm.com/download/win"
}
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Fail "docker is not installed. Install Docker Desktop from https://www.docker.com/products/docker-desktop/"
}

# "docker info" fails when the engine is not actually running, which is the
# usual case on Windows: Docker Desktop installed but not started.
docker info *> $null
if ($LASTEXITCODE -ne 0) {
    Fail "Docker is installed but not running. Start Docker Desktop, wait for the whale icon to settle, then run this again."
}
Write-Host "git and docker are available"

# --- clone or update ---------------------------------------------------
Step "Fetching the project into $Dir"
if (-not (Test-Path $Root)) { New-Item -ItemType Directory -Force $Root | Out-Null }

if (Test-Path (Join-Path $Dir '.git')) {
    Write-Host "Already cloned - pulling the latest changes"
    git -C $Dir pull --ff-only
} else {
    if (Test-Path $Dir) { Fail "$Dir exists but is not a git clone. Move or delete it, then re-run." }
    git clone --depth 1 $RepoUrl $Dir
}
Set-Location $Dir

# --- free the port -----------------------------------------------------
if (docker ps -a --filter "name=^/$Container$" --format '{{.Names}}') {
    Write-Host "Removing the previous container"
    docker rm -f $Container *> $null
}

# --- build -------------------------------------------------------------
Step 'Building the image'
Write-Host "This downloads the 44 MB dataset and trains the model."
Write-Host "First build takes about 5-8 minutes. Later builds are cached." -ForegroundColor Yellow
docker build -t $Image $Dir
if ($LASTEXITCODE -ne 0) { Fail 'docker build failed - see the output above.' }

# --- run ---------------------------------------------------------------
Step 'Starting the container'
docker run -d --name $Container -p "${Port}:5000" $Image | Out-Null
if ($LASTEXITCODE -ne 0) { Fail "docker run failed. Is port $Port already in use?" }

# Wait for Flask to answer rather than guessing a sleep duration.
$url = "http://localhost:$Port"
$ok = $false
foreach ($i in 1..40) {
    Start-Sleep -Seconds 2
    try {
        if ((Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 5).StatusCode -eq 200) { $ok = $true; break }
    } catch { }
}

if ($ok) {
    Write-Host "`n========================================================" -ForegroundColor Green
    Write-Host "  Malicious URL Detection is running" -ForegroundColor Green
    Write-Host "  URL: $url" -ForegroundColor Green
    Write-Host "========================================================" -ForegroundColor Green
    Write-Host "`n  Try:  github.com                 -> Benign"
    Write-Host "        104.211.28.157/powerpc     -> Malicious"
    Write-Host "`n  Logs:  docker logs -f $Container"
    Write-Host "  Stop:  docker rm -f $Container`n"
    Start-Process $url
} else {
    Write-Host "`nThe container started but did not answer on $url." -ForegroundColor Yellow
    Write-Host "Check what it is doing with:  docker logs $Container`n"
}
