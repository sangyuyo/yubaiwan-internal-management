param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[a-zA-Z0-9][a-zA-Z0-9.-]*$')]
    [string] $Server,

    [Parameter(Mandatory)]
    [ValidatePattern('^[a-zA-Z_][a-zA-Z0-9_.-]*$')]
    [string] $User,

    [ValidateRange(1, 65535)]
    [int] $Port = 22,

    [string] $IdentityFile,

    [switch] $VerifyPoster,

    [switch] $VerifyQscCandidate
)

$ErrorActionPreference = 'Stop'
$workspace = Split-Path -Parent $PSScriptRoot
$baseline = Join-Path $workspace '源码基线'
$working = Join-Path $workspace '接管工作副本'
$manifest = Get-Content -LiteralPath (Join-Path $baseline 'manifest.json') -Raw | ConvertFrom-Json

function Export-VerifiedSource($File, $Name, $ExpectedHash) {
    if ($ExpectedHash -and (Get-FileHash -LiteralPath $File -Algorithm SHA256).Hash -ine $ExpectedHash) {
        throw "源码哈希不匹配：$Name"
    }
    @{
        name = $Name
        content = [Convert]::ToBase64String([IO.File]::ReadAllBytes($File))
    }
}

$files = @(foreach ($item in $manifest) {
    if ($VerifyQscCandidate -and $item.path -eq 'kitchen-clean/server.js') {
        Export-VerifiedSource (Join-Path $working $item.path) $item.path $null
    } else {
        Export-VerifiedSource (Join-Path $baseline $item.path) $item.path $item.sha256
    }
    if ($item.path.StartsWith('shop-performance/')) {
        $pathForTest = $item.path.Replace('shop-performance/', 'shop-candidate/')
        $expected = $item.sha256
        if ($item.path -in @('shop-performance/server.js','shop-performance/db.js','shop-performance/parsers/meituan_guandian.js','shop-performance/public/index.html','shop-performance/public/css/app.css')) { $expected = $null }
        Export-VerifiedSource (Join-Path $working $item.path) $pathForTest $expected
    }
})
foreach ($added in @('public/dashboard-tools.js')) {
    $files += Export-VerifiedSource (Join-Path $working "shop-performance/$added") "shop-candidate/$added" $null
}
$runner = Join-Path $PSScriptRoot '实际服务.cjs'
$payload = @{
    files = $files
    runner = [Convert]::ToBase64String([IO.File]::ReadAllBytes($runner))
    qscCandidate = $VerifyQscCandidate.IsPresent
} | ConvertTo-Json -Depth 6 -Compress

$sshArgs = @('-p', $Port, '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
    '-o', 'UpdateHostKeys=no', '-o', 'ConnectTimeout=8', '-o', 'ClearAllForwardings=yes', '-T')
if ($IdentityFile) {
    if (-not (Test-Path -LiteralPath $IdentityFile -PathType Leaf)) { throw '指定的密钥文件不存在。' }
    $sshArgs += @('-i', $IdentityFile, '-o', 'IdentitiesOnly=yes')
}

$bootstrap = @'
node -e 'const fs = require("node:fs"); const payload = JSON.parse(fs.readFileSync(0, "utf8")); const code = Buffer.from(payload.runner, "base64").toString("utf8"); new Function("require", "fixtureInput", code)(require, payload);'
'@
$output = $payload | & ssh.exe @sshArgs "$User@$Server" $bootstrap
if ($LASTEXITCODE -ne 0) { throw "隔离联调失败，SSH 退出码 $LASTEXITCODE。" }

$result = $output | ConvertFrom-Json
$result.checks | ForEach-Object { "通过：$_" }
if ($VerifyPoster) {
    $result.fixture | ConvertTo-Json -Depth 40 -Compress | & node (Join-Path $PSScriptRoot '通晒浏览器.cjs')
    if ($LASTEXITCODE -ne 0) { throw '通晒浏览器验证失败。' }
}
