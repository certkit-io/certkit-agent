$ErrorActionPreference = "Stop"

$serviceName = if ($env:CERTKIT_SERVICE_NAME) { $env:CERTKIT_SERVICE_NAME } else { "certkit-agent" }
$configPath = if ($env:CERTKIT_CONFIG_PATH) { $env:CERTKIT_CONFIG_PATH } else { "C:\\ProgramData\\CertKit\\certkit-agent\\config.json" }
$source = if ($env:CERTKIT_AGENT_SOURCE) { $env:CERTKIT_AGENT_SOURCE } else { "release" }
$version = $env:CERTKIT_VERSION

Write-Host "Starting Apache + CertKit Agent (source=$source)"

$agentIdPath = "C:\\ProgramData\\CertKit\\agent-id"
$agentId = "7f3d2c91-3b78-4e12-9b21-8e6e0f4b0c75"
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $agentIdPath) | Out-Null
Set-Content -Path $agentIdPath -Value $agentId -Encoding ASCII

if ($source -eq "release") {
    if ($version) {
        & C:\app\install.ps1 -ServiceName $serviceName -ConfigPath $configPath -Version $version
    } else {
        & C:\app\install.ps1 -ServiceName $serviceName -ConfigPath $configPath
    }
} elseif ($source -eq "local") {
    $bin = if ($env:CERTKIT_AGENT_BINARY) { $env:CERTKIT_AGENT_BINARY } else { "C:\\opt\\certkit-agent\\certkit-agent.exe" }
    if (-not (Test-Path $bin)) {
        throw "Local binary not found at $bin. Set CERTKIT_AGENT_BINARY or mount the file."
    }
    & $bin install --service-name $serviceName --config $configPath
} else {
    throw "Unsupported CERTKIT_AGENT_SOURCE: $source"
}

function Get-ApacheHome {
    $candidates = @(
        "C:\\Apache24",
        "C:\\tools\\Apache24",
        "C:\\Program Files\\Apache Group\\Apache2",
        "C:\\Apache2"
    )
    foreach ($path in $candidates) {
        if (Test-Path (Join-Path $path "bin\\httpd.exe")) {
            return $path
        }
    }
    throw "Apache installation not found. Ensure Apache is installed in the image."
}

$apacheHome = Get-ApacheHome
$apacheHomeUnix = $apacheHome -replace "\\\\", "/"

$docRoot = "C:\\inetpub\\apache"
$docRootUnix = $docRoot -replace "\\\\", "/"
if (-not (Test-Path $docRoot)) {
    New-Item -ItemType Directory -Force -Path $docRoot | Out-Null
}
$indexPath = Join-Path $docRoot "index.html"
if (-not (Test-Path $indexPath)) {
    @"
<html>
  <head><title>Apache (Windows) + CertKit</title></head>
  <body><h1>Apache on Windows container is running.</h1></body>
</html>
"@ | Set-Content -Path $indexPath -Encoding UTF8
}

$sslDir = Join-Path $apacheHome "conf\\ssl"
if (-not (Test-Path $sslDir)) {
    New-Item -ItemType Directory -Force -Path $sslDir | Out-Null
}
$certPath = Join-Path $sslDir "certkit.crt"
$keyPath = Join-Path $sslDir "certkit.key"
$certPathUnix = $certPath -replace "\\\\", "/"
$keyPathUnix = $keyPath -replace "\\\\", "/"


$openssl = "C:\\Apache24\\bin\\openssl.exe"


if (-not (Test-Path $certPath) -or -not (Test-Path $keyPath)) {
    & $openssl req -x509 -nodes -newkey rsa:2048 -subj "/CN=localhost" `
        -keyout $keyPath -out $certPath -days 365 | Out-Null
    Write-Host "Generated self-signed certificate for Apache."
}

$httpdConf = @"
Define SRVROOT "$apacheHomeUnix"
ServerRoot "$apacheHomeUnix"

Listen 443

LoadModule authz_core_module modules/mod_authz_core.so
LoadModule authz_host_module modules/mod_authz_host.so
LoadModule dir_module modules/mod_dir.so
LoadModule mime_module modules/mod_mime.so
LoadModule log_config_module modules/mod_log_config.so
LoadModule alias_module modules/mod_alias.so
LoadModule ssl_module modules/mod_ssl.so
LoadModule socache_shmcb_module modules/mod_socache_shmcb.so

ServerName localhost

DocumentRoot "$docRootUnix"
<Directory "$docRootUnix">
    Require all granted
    AllowOverride None
</Directory>

ErrorLog "logs/error.log"
CustomLog "logs/access.log" common

Include conf/extra/httpd-ssl.conf
"@

$sslConf = @"
<VirtualHost _default_:443>
    ServerName localhost
    DocumentRoot "$docRootUnix"
    SSLEngine on
    SSLCertificateFile "$certPathUnix"
    SSLCertificateKeyFile "$keyPathUnix"
</VirtualHost>
"@

Set-Content -Path (Join-Path $apacheHome "conf\\httpd.conf") -Value $httpdConf -Encoding UTF8
Set-Content -Path (Join-Path $apacheHome "conf\\extra\\httpd-ssl.conf") -Value $sslConf -Encoding UTF8

& (Join-Path $apacheHome "bin\\httpd.exe") -t

try {
    & (Join-Path $apacheHome "bin\\httpd.exe") -DFOREGROUND
    powershell -NoProfile -Command "Get-Content C:\dev\apache-windows\certkit-agent.log -Tail 20 -Wait"
} finally {
    try { Stop-Service $serviceName -Force -ErrorAction SilentlyContinue } catch {}
}
