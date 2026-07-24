param(
    [Parameter(Mandatory)][string]$PackageDirectory,
    [Parameter(Mandatory)][string]$EntryPoint,
    [Parameter(Mandatory)][string]$PackageVersion,
    [Parameter(Mandatory)][string]$PrivateKeyPem,
    [Parameter(Mandatory)][string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'
$package = (Resolve-Path -LiteralPath $PackageDirectory).Path
$entry = [IO.Path]::GetFileName($EntryPoint)
if ($entry -ne $EntryPoint -or -not (Test-Path -LiteralPath (Join-Path $package $entry) -PathType Leaf)) {
    throw 'EntryPoint must be a filename present directly in PackageDirectory.'
}

$files = Get-ChildItem -LiteralPath $package -File |
    Where-Object Extension -ne '.pdb' |
    Sort-Object Name |
    ForEach-Object {
        [ordered]@{
            name = $_.Name
            sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            size = $_.Length
        }
    }
$document = [ordered]@{
    formatVersion = 1
    packageVersion = $PackageVersion
    entryPoint = $entry
    files = @($files)
}
$json = $document | ConvertTo-Json -Depth 5 -Compress
$bytes = [Text.Encoding]::UTF8.GetBytes($json)
$signer = [Security.Cryptography.ECDsa]::Create()
try {
    $signer.ImportFromPem((Get-Content -LiteralPath $PrivateKeyPem -Raw))
    $signature = $signer.SignData($bytes, [Security.Cryptography.HashAlgorithmName]::SHA256)
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    [IO.File]::WriteAllBytes((Join-Path $OutputDirectory 'worker-manifest.json'), $bytes)
    [IO.File]::WriteAllBytes((Join-Path $OutputDirectory 'worker-manifest.sig'), $signature)
    [IO.File]::WriteAllBytes(
        (Join-Path $OutputDirectory 'worker-manifest-public-key.der'),
        $signer.ExportSubjectPublicKeyInfo())
}
finally {
    $signer.Dispose()
}
