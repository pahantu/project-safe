$ErrorActionPreference='Stop'
& (Join-Path $PSScriptRoot 'build.ps1')
$testOutput=Join-Path $PSScriptRoot 'artifacts\tests'
New-Item -ItemType Directory -Path $testOutput -Force | Out-Null
$testExe=Join-Path $PSScriptRoot 'Сейф проекта.exe'
$process=Start-Process -FilePath $testExe -ArgumentList @('--test',('"'+$testOutput+'"')) -PassThru -Wait
if($process.ExitCode -ne 0){throw ('Tests failed. See '+(Join-Path $testOutput 'tests.json'))}
$result=Get-Content -LiteralPath (Join-Path $testOutput 'tests.json') -Raw | ConvertFrom-Json
if($result.Failed -ne 0 -or $result.Total -lt 41){throw 'Incomplete or failed test run'}
Write-Output ('PASS: '+$result.Total+' scenarios')
