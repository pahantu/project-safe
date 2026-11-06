$ErrorActionPreference='Stop'
$compiler=Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if(!(Test-Path -LiteralPath $compiler)){throw 'Не найден компилятор .NET Framework 4.x.'}
$sources=Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'src') -File -Filter '*.cs' | ForEach-Object {$_.FullName}
& $compiler /nologo /target:winexe /optimize+ /platform:anycpu /codepage:65001 /r:System.Drawing.dll /r:System.Windows.Forms.dll /r:System.Web.Extensions.dll /r:System.Xml.dll /r:System.Core.dll ('/out:'+(Join-Path $PSScriptRoot 'Сейф проекта.exe')) $sources
if($LASTEXITCODE -ne 0){throw 'Ошибка сборки'}
