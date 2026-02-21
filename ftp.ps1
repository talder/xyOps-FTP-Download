#requires -Version 7.0
# Copyright (c) 2026 Tim Alderweireldt. All rights reserved.
<#!
xyOps FTP Download Event Plugin (PowerShell 7)
Download files from remote servers via FTP, FTPS (Explicit/Implicit), or SFTP.

Protocols:
- FTP  : Plain FTP via .NET System.Net.FtpWebRequest (port 21)
- FTPS : FTP over TLS — Explicit (STARTTLS, port 21) via .NET, Implicit (port 990) via TcpClient+SslStream
- SFTP : SSH File Transfer Protocol via Posh-SSH module (port 22)

I/O contract:
- Read one JSON object from STDIN (job), write progress/messages as JSON lines of the
  form: { "xy": 1, ... } to STDOUT.
- On success, emit: { "xy": 1, "code": 0, "data": <result>, "files": [...], "description": "..." }
- On error, emit:   { "xy": 1, "code": <nonzero>, "description": "..." } and exit 1.

Test locally:
  pwsh -NoProfile -ExecutionPolicy Bypass -File .\ftp.ps1 < job.json
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region xyOps Output Helpers

function Write-XY {
  param([hashtable]$Object)
  $payload = [ordered]@{ xy = 1 }
  foreach ($k in $Object.Keys) { $payload[$k] = $Object[$k] }
  [Console]::Out.WriteLine(($payload | ConvertTo-Json -Depth 20 -Compress))
  [Console]::Out.Flush()
}

function Write-XYProgress {
  param([double]$Value, [string]$Status)
  $o = @{ progress = [math]::Round($Value, 4) }
  if ($Status) { $o.status = $Status }
  Write-XY $o
}

function Write-XYSuccess {
  param($Data, [string]$Description, [array]$Files = @())
  $o = @{ code = 0; data = $Data }
  if ($Description) { $o.description = $Description }
  if ($Files.Count -gt 0) { $o.files = $Files }
  Write-XY $o
}

function Write-XYError {
  param([int]$Code, [string]$Description)
  Write-XY @{ code = $Code; description = $Description }
}

function Read-JobFromStdin {
  $raw = [Console]::In.ReadToEnd()
  if ([string]::IsNullOrWhiteSpace($raw)) { throw 'No job JSON received on STDIN' }
  return $raw | ConvertFrom-Json -ErrorAction Stop
}

function Get-Param {
  param($Params, [string]$Name, $Default = $null)
  if ($Params.PSObject.Properties.Name -contains $Name) { return $Params.$Name }
  return $Default
}

#endregion

#region Module Installer

function Install-RequiredModules {
  param([string]$Protocol)

  if ($Protocol -ne 'sftp') { return }

  if (-not (Get-Module -ListAvailable -Name 'Posh-SSH')) {
    Write-XYProgress 0.05 'Installing Posh-SSH module (first-time SFTP setup)...'
    try {
      Install-Module -Name 'Posh-SSH' -Scope CurrentUser -Force -AllowClobber -SkipPublisherCheck
      Write-XYProgress 0.08 'Posh-SSH module installed successfully'
    }
    catch {
      throw ("Failed to install Posh-SSH module. Install manually: Install-Module -Name Posh-SSH -Scope CurrentUser -Force`n" +
             "Error: $($_.Exception.Message)")
    }
  }

  Import-Module Posh-SSH -ErrorAction Stop
}

#endregion

#region Error Handling

function Format-TransferError {
  param(
    [System.Management.Automation.ErrorRecord]$ErrorRecord,
    [string]$Phase,
    [string]$Protocol
  )

  $msg = $ErrorRecord.Exception.Message
  $innerMsg = if ($ErrorRecord.Exception.InnerException) { $ErrorRecord.Exception.InnerException.Message } else { '' }
  $fullMsg = if ($innerMsg) { "$msg — $innerMsg" } else { $msg }

  $category = 'Unknown'
  $suggestion = ''

  switch -Regex ($fullMsg) {
    'No such host|DNS|name.*resolution|could not resolve' {
      $category = 'Connection — DNS Resolution'
      $suggestion = 'Verify the hostname is correct and DNS is reachable'
      break
    }
    'actively refused|connection refused|ECONNREFUSED' {
      $category = 'Connection — Refused'
      $suggestion = "Verify the server is running and listening on the correct port for $Protocol"
      break
    }
    'timed? ?out|ETIMEDOUT' {
      $category = 'Connection — Timeout'
      $suggestion = 'Check firewall rules and network connectivity'
      break
    }
    'unreachable|EHOSTUNREACH|ENETUNREACH' {
      $category = 'Connection — Unreachable'
      $suggestion = 'Verify network connectivity and routing to the server'
      break
    }
    '530|not log|login.*fail|auth.*fail|invalid.*credential|access denied.*login|permission denied.*publickey' {
      $category = 'Authentication — Failed'
      $suggestion = 'Verify username/password or SSH key. Check if the account is active and not locked.'
      break
    }
    'key.*invalid|key.*not.*found|private.*key|bad.*key|key.*format' {
      $category = 'Authentication — SSH Key Error'
      $suggestion = 'Verify the SSH key file exists, is readable, and in the correct format (RSA/ED25519/ECDSA/DSA)'
      break
    }
    'passphrase|decrypt.*key' {
      $category = 'Authentication — Key Passphrase'
      $suggestion = 'The SSH key is encrypted. Provide the correct passphrase via parameter or FTP_SSH_KEY_PASSPHRASE secret.'
      break
    }
    '550.*permission|553|access.*denied|permission.*denied|not.*authorized' {
      $category = 'Permission — Access Denied'
      $suggestion = 'The user does not have read permission on the remote path. Check directory permissions on the server.'
      break
    }
    '550.*no such|550.*not found|no such file|directory.*not.*exist' {
      $category = 'Permission — Path Not Found'
      $suggestion = 'The remote path does not exist. Verify the path is correct.'
      break
    }
    '552|disk.*full|no space|quota.*exceeded' {
      $category = 'Transfer — Disk Full'
      $suggestion = 'The local disk has insufficient space'
      break
    }
    '451|transfer.*abort|download.*fail|read.*fail' {
      $category = 'Transfer — Failed'
      $suggestion = 'The file transfer was interrupted. Check server logs and retry.'
      break
    }
    'SSL|TLS|certificate|handshake|secure.*channel' {
      $category = 'Protocol — TLS/SSL Error'
      $suggestion = "Check TLS configuration. For FTPS, verify the server supports the selected mode (Explicit/Implicit)."
      break
    }
    'STARTTLS|AUTH TLS' {
      $category = 'Protocol — STARTTLS Failed'
      $suggestion = 'The server does not support FTPS Explicit (STARTTLS). Try Implicit mode or plain FTP.'
      break
    }
  }

  if ($category -eq 'Unknown') {
    $category = "$Phase — Error"
    $suggestion = 'Check the error details and server configuration'
  }

  Write-XY @{ table = @{
    title = 'Error Details'
    header = @('Property', 'Value')
    rows = @(
      @('Category', $category),
      @('Phase', $Phase),
      @('Protocol', $Protocol.ToUpper()),
      @('Details', $fullMsg),
      @('Suggestion', $suggestion)
    )
    caption = ''
  } }

  return "${category}: $fullMsg"
}

#endregion

#region FTP/FTPS Explicit Operations (.NET FtpWebRequest)

function New-FTPRequest {
  param(
    [string]$Url,
    [string]$Method,
    [System.Net.NetworkCredential]$Credential,
    [bool]$EnableSsl,
    [bool]$PassiveMode
  )

  if ($EnableSsl) {
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { param($s, $c, $ch, $e) $true }
  }

  $request = [System.Net.FtpWebRequest]::Create($Url)
  $request.Method = $Method
  $request.Credentials = $Credential
  $request.EnableSsl = $EnableSsl
  $request.UsePassive = $PassiveMode
  $request.UseBinary = $true
  $request.KeepAlive = $false

  return $request
}

function Get-FTPBaseUrl {
  param([string]$HostName, [int]$Port)
  return "ftp://${HostName}:${Port}"
}

function Get-FTPFileList {
  param(
    [string]$BaseUrl,
    [string]$RemotePath,
    [System.Net.NetworkCredential]$Credential,
    [bool]$EnableSsl,
    [bool]$PassiveMode,
    [bool]$Recursive
  )

  $files = [System.Collections.ArrayList]::new()
  $url = "$BaseUrl/$($RemotePath.TrimStart('/'))"

  try {
    $request = New-FTPRequest -Url $url -Method ([System.Net.WebRequestMethods+Ftp]::ListDirectoryDetails) `
                              -Credential $Credential -EnableSsl $EnableSsl -PassiveMode $PassiveMode
    $response = $request.GetResponse()
    $stream = $response.GetResponseStream()
    $reader = [System.IO.StreamReader]::new($stream)

    while (-not $reader.EndOfStream) {
      $line = $reader.ReadLine()
      if ($line -match '^([d-])([rwx-]{9})\s+\d+\s+\S+\s+\S+\s+(\d+)\s+(\S+\s+\S+\s+\S+)\s+(.+)$') {
        $isDir = $Matches[1] -eq 'd'
        $size = [long]$Matches[3]
        $name = $Matches[5]

        if ($name -eq '.' -or $name -eq '..') { continue }

        $fullPath = "$RemotePath/$name".TrimStart('/')
        if ($isDir -and $Recursive) {
          $subFiles = Get-FTPFileList -BaseUrl $BaseUrl -RemotePath $fullPath -Credential $Credential `
                                      -EnableSsl $EnableSsl -PassiveMode $PassiveMode -Recursive $true
          foreach ($sub in $subFiles) { $null = $files.Add($sub) }
        }
        elseif (-not $isDir) {
          $null = $files.Add(@{ Path = $fullPath; Size = $size; Name = $name })
        }
      }
    }

    $reader.Close()
    $response.Close()
  }
  catch {}

  return $files.ToArray()
}

function Get-FTPSingleFile {
  param(
    [string]$BaseUrl,
    [string]$RemoteFile,
    [string]$LocalPath,
    [System.Net.NetworkCredential]$Credential,
    [bool]$EnableSsl,
    [bool]$PassiveMode
  )

  $url = "$BaseUrl/$($RemoteFile.TrimStart('/'))"
  $request = New-FTPRequest -Url $url -Method ([System.Net.WebRequestMethods+Ftp]::DownloadFile) `
                            -Credential $Credential -EnableSsl $EnableSsl -PassiveMode $PassiveMode

  $response = $request.GetResponse()
  $stream = $response.GetResponseStream()

  $fileStream = [System.IO.File]::Create($LocalPath)
  try {
    $stream.CopyTo($fileStream)
  }
  finally {
    $fileStream.Close()
  }

  $response.Close()

  return (Get-Item $LocalPath).Length
}

function Remove-FTPFile {
  param(
    [string]$BaseUrl,
    [string]$RemoteFile,
    [System.Net.NetworkCredential]$Credential,
    [bool]$EnableSsl,
    [bool]$PassiveMode
  )

  $url = "$BaseUrl/$($RemoteFile.TrimStart('/'))"
  $request = New-FTPRequest -Url $url -Method ([System.Net.WebRequestMethods+Ftp]::DeleteFile) `
                            -Credential $Credential -EnableSsl $EnableSsl -PassiveMode $PassiveMode
  $response = $request.GetResponse()
  $response.Close()
}

#endregion

#region FTPS Implicit Operations (TcpClient + SslStream)

function Read-FTPSResponse {
  param([System.IO.StreamReader]$Reader)

  $line = $Reader.ReadLine()
  if ($null -eq $line) { throw 'Connection closed by remote server' }

  while ($line -match '^\d{3}-') {
    $nextLine = $Reader.ReadLine()
    if ($null -eq $nextLine) { break }
    $line = $nextLine
  }

  $code = 0
  $message = $line
  if ($line -match '^(\d{3})\s?(.*)') {
    $code = [int]$Matches[1]
    $message = $Matches[2]
  }

  return @{ Code = $code; Text = $line; Message = $message }
}

function New-ImplicitFTPSSession {
  param([string]$HostName, [int]$Port, [string]$Username, [string]$Password)

  $tcpClient = [System.Net.Sockets.TcpClient]::new()
  $tcpClient.Connect($HostName, $Port)

  $sslCallback = [System.Net.Security.RemoteCertificateValidationCallback]{
    param($sender, $certificate, $chain, $sslPolicyErrors)
    return $true
  }

  $sslStream = [System.Net.Security.SslStream]::new(
    $tcpClient.GetStream(), $false, $sslCallback
  )
  $sslStream.AuthenticateAsClient($HostName)

  $reader = [System.IO.StreamReader]::new($sslStream, [System.Text.Encoding]::UTF8)
  $writer = [System.IO.StreamWriter]::new($sslStream, [System.Text.Encoding]::UTF8)
  $writer.AutoFlush = $true

  $resp = Read-FTPSResponse -Reader $reader
  if ($resp.Code -ge 400) { throw "Server rejected connection: $($resp.Text)" }

  $writer.WriteLine("USER $Username")
  $resp = Read-FTPSResponse -Reader $reader
  if ($resp.Code -ge 400 -and $resp.Code -ne 331) { throw "USER command failed: $($resp.Text)" }

  $writer.WriteLine("PASS $Password")
  $resp = Read-FTPSResponse -Reader $reader
  if ($resp.Code -ge 400) { throw "Authentication failed: $($resp.Text)" }

  $writer.WriteLine("TYPE I")
  $null = Read-FTPSResponse -Reader $reader

  $writer.WriteLine("PBSZ 0")
  $null = Read-FTPSResponse -Reader $reader

  $writer.WriteLine("PROT P")
  $null = Read-FTPSResponse -Reader $reader

  return @{
    Client    = $tcpClient
    SslStream = $sslStream
    Reader    = $reader
    Writer    = $writer
    HostName  = $HostName
  }
}

function Close-ImplicitFTPSSession {
  param([hashtable]$Session)

  try { $Session.Writer.WriteLine("QUIT"); $null = Read-FTPSResponse -Reader $Session.Reader } catch {}
  try { $Session.Reader.Dispose() } catch {}
  try { $Session.Writer.Dispose() } catch {}
  try { $Session.SslStream.Dispose() } catch {}
  try { $Session.Client.Dispose() } catch {}
}

function Open-ImplicitFTPSDataChannel {
  param([hashtable]$Session)

  $Session.Writer.WriteLine("PASV")
  $resp = Read-FTPSResponse -Reader $Session.Reader

  if ($resp.Text -match '\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)') {
    $dataPort = [int]$Matches[5] * 256 + [int]$Matches[6]
  }
  else {
    throw "Failed to parse PASV response: $($resp.Text)"
  }

  $dataClient = [System.Net.Sockets.TcpClient]::new()
  $dataClient.Connect($Session.HostName, $dataPort)

  $sslCallback = [System.Net.Security.RemoteCertificateValidationCallback]{
    param($sender, $certificate, $chain, $sslPolicyErrors)
    return $true
  }

  $dataSsl = [System.Net.Security.SslStream]::new(
    $dataClient.GetStream(), $false, $sslCallback
  )
  $dataSsl.AuthenticateAsClient($Session.HostName)

  return @{ Client = $dataClient; SslStream = $dataSsl }
}

function Get-ImplicitFTPSFileList {
  param([hashtable]$Session, [string]$RemotePath, [bool]$Recursive)

  $files = [System.Collections.ArrayList]::new()
  $dataChannel = Open-ImplicitFTPSDataChannel -Session $Session

  try {
    $Session.Writer.WriteLine("LIST $RemotePath")
    $resp = Read-FTPSResponse -Reader $Session.Reader
    if ($resp.Code -ge 400) { throw "LIST command failed: $($resp.Text)" }

    $streamReader = [System.IO.StreamReader]::new($dataChannel.SslStream, [System.Text.Encoding]::UTF8)
    while (-not $streamReader.EndOfStream) {
      $line = $streamReader.ReadLine()
      if ($line -match '^([d-])([rwx-]{9})\s+\d+\s+\S+\s+\S+\s+(\d+)\s+(\S+\s+\S+\s+\S+)\s+(.+)$') {
        $isDir = $Matches[1] -eq 'd'
        $size = [long]$Matches[3]
        $name = $Matches[5]

        if ($name -eq '.' -or $name -eq '..') { continue }

        $fullPath = "$RemotePath/$name".TrimStart('/')
        if ($isDir -and $Recursive) {
          $subFiles = Get-ImplicitFTPSFileList -Session $Session -RemotePath $fullPath -Recursive $true
          foreach ($sub in $subFiles) { $null = $files.Add($sub) }
        }
        elseif (-not $isDir) {
          $null = $files.Add(@{ Path = $fullPath; Size = $size; Name = $name })
        }
      }
    }
  }
  finally {
    try { $dataChannel.SslStream.Close() } catch {}
    try { $dataChannel.Client.Close() } catch {}
  }

  $null = Read-FTPSResponse -Reader $Session.Reader

  return $files.ToArray()
}

function Get-ImplicitFTPSSingleFile {
  param([hashtable]$Session, [string]$RemoteFile, [string]$LocalPath)

  $dataChannel = Open-ImplicitFTPSDataChannel -Session $Session

  try {
    $Session.Writer.WriteLine("RETR $RemoteFile")
    $resp = Read-FTPSResponse -Reader $Session.Reader
    if ($resp.Code -ge 400) { throw "RETR command failed: $($resp.Text)" }

    $fileStream = [System.IO.File]::Create($LocalPath)
    try {
      $dataChannel.SslStream.CopyTo($fileStream)
    }
    finally {
      $fileStream.Close()
    }
  }
  finally {
    try { $dataChannel.SslStream.Close() } catch {}
    try { $dataChannel.Client.Close() } catch {}
  }

  $null = Read-FTPSResponse -Reader $Session.Reader

  return (Get-Item $LocalPath).Length
}

function Remove-ImplicitFTPSFile {
  param([hashtable]$Session, [string]$RemoteFile)

  $Session.Writer.WriteLine("DELE $RemoteFile")
  $resp = Read-FTPSResponse -Reader $Session.Reader
  if ($resp.Code -ge 400) { throw "DELE command failed: $($resp.Text)" }
}

#endregion

#region SFTP Operations (Posh-SSH)

function New-SFTPConnection {
  param(
    [string]$HostName,
    [int]$Port,
    [string]$Username,
    [string]$Password,
    [string]$KeyPath,
    [string]$KeyPassphrase
  )

  $securePass = if ($KeyPath -and $KeyPassphrase) {
    ConvertTo-SecureString $KeyPassphrase -AsPlainText -Force
  }
  elseif ($Password) {
    ConvertTo-SecureString $Password -AsPlainText -Force
  }
  else {
    [System.Security.SecureString]::new()
  }

  $credential = [System.Management.Automation.PSCredential]::new($Username, $securePass)

  $sessionParams = @{
    ComputerName = $HostName
    Port         = $Port
    Credential   = $credential
    AcceptKey    = $true
    Force        = $true
    ErrorAction  = 'Stop'
  }

  if ($KeyPath) {
    if (-not (Test-Path $KeyPath)) {
      throw "SSH key file not found: $KeyPath"
    }
    $sessionParams['KeyFile'] = $KeyPath
  }

  $session = New-SFTPSession @sessionParams
  return $session
}

function Get-SFTPFileList {
  param([int]$SessionId, [string]$RemotePath, [bool]$Recursive)

  $files = [System.Collections.ArrayList]::new()

  try {
    $items = Get-SFTPChildItem -SessionId $SessionId -Path $RemotePath -ErrorAction Stop

    foreach ($item in $items) {
      if ($item.Name -eq '.' -or $item.Name -eq '..') { continue }

      if ($item.IsDirectory -and $Recursive) {
        $subFiles = Get-SFTPFileList -SessionId $SessionId -RemotePath $item.FullName -Recursive $true
        foreach ($sub in $subFiles) { $null = $files.Add($sub) }
      }
      elseif (-not $item.IsDirectory) {
        $null = $files.Add(@{ Path = $item.FullName; Size = $item.Length; Name = $item.Name })
      }
    }
  }
  catch {}

  return $files.ToArray()
}

function Get-SFTPSingleFile {
  param([int]$SessionId, [string]$RemoteFile, [string]$LocalPath)

  $localDir = [System.IO.Path]::GetDirectoryName($LocalPath)
  $localFileName = [System.IO.Path]::GetFileName($LocalPath)
  $remoteFileName = [System.IO.Path]::GetFileName($RemoteFile)

  # Get-SFTPItem requires destination to be a directory
  Get-SFTPItem -SessionId $SessionId -Path $RemoteFile -Destination $localDir -Force -ErrorAction Stop

  # If downloaded filename differs from desired, rename it
  $downloadedPath = [System.IO.Path]::Combine($localDir, $remoteFileName)
  if ($localFileName -ne $remoteFileName) {
    Move-Item -Path $downloadedPath -Destination $LocalPath -Force
  }

  return (Get-Item $LocalPath).Length
}

function Remove-SFTPFile {
  param([int]$SessionId, [string]$RemoteFile)

  Remove-SFTPItem -SessionId $SessionId -Path $RemoteFile -Force -ErrorAction Stop
}

function Close-SFTPConnection {
  param([int]$SessionId)

  try { Remove-SFTPSession -SessionId $SessionId -ErrorAction SilentlyContinue | Out-Null } catch {}
}

#endregion

#region File Name Utilities

function Get-UniqueFileName {
  param([string]$FilePath)

  $dir = [System.IO.Path]::GetDirectoryName($FilePath)
  $name = [System.IO.Path]::GetFileNameWithoutExtension($FilePath)
  $ext = [System.IO.Path]::GetExtension($FilePath)
  $timestamp = [datetime]::Now.ToString('yyyyMMdd_HHmmss')

  $newName = "${name}_${timestamp}${ext}"
  return [System.IO.Path]::Combine($dir, $newName)
}

function Test-MatchesGlob {
  param([string]$Path, [string]$Pattern)

  $regexPattern = $Pattern.Replace('.', '\.').Replace('*', '.*').Replace('?', '.')
  return $Path -match "^${regexPattern}$"
}

#endregion

#region Main Orchestrator

function Invoke-FTPDownload {
  param($Params, [string]$Cwd)

  Write-XYProgress 0.02 'Starting FTP Download...'

  # Resolve parameters with secret vault fallback
  $protocol = (Get-Param $Params 'protocol' 'ftp').ToLower()

  $ftpHost = (Get-Param $Params 'host' '').Trim()
  if (-not $ftpHost) { $ftpHost = if ($env:FTP_HOST) { $env:FTP_HOST.Trim() } else { '' } }

  $portStr = (Get-Param $Params 'port' '').ToString().Trim()
  if (-not $portStr) { $portStr = if ($env:FTP_PORT) { $env:FTP_PORT.Trim() } else { '' } }

  $username = (Get-Param $Params 'username' '').Trim()
  if (-not $username) { $username = if ($env:FTP_USERNAME) { $env:FTP_USERNAME.Trim() } else { '' } }

  $password = (Get-Param $Params 'password' '').Trim()
  if (-not $password) { $password = if ($env:FTP_PASSWORD) { $env:FTP_PASSWORD.Trim() } else { '' } }

  $ftpsMode = (Get-Param $Params 'ftpsMode' 'explicit').ToLower()

  $sshKeyPath = (Get-Param $Params 'sshKeyPath' '').Trim()
  if (-not $sshKeyPath) { $sshKeyPath = if ($env:FTP_SSH_KEY_PATH) { $env:FTP_SSH_KEY_PATH.Trim() } else { '' } }

  $sshKeyPassphrase = (Get-Param $Params 'sshKeyPassphrase' '').Trim()
  if (-not $sshKeyPassphrase) { $sshKeyPassphrase = if ($env:FTP_SSH_KEY_PASSPHRASE) { $env:FTP_SSH_KEY_PASSPHRASE.Trim() } else { '' } }

  $remotePath     = (Get-Param $Params 'remotePath' '').Trim()
  $localPath      = (Get-Param $Params 'localPath' '').Trim()
  $downloadMode   = (Get-Param $Params 'downloadMode' 'file').ToLower()
  $ifFileExists   = (Get-Param $Params 'ifFileExists' 'overwrite').ToLower()
  $deleteAfter    = if ($Params.PSObject.Properties.Name -contains 'deleteAfterDownload') { [bool]$Params.deleteAfterDownload } else { $false }
  $createLocalDirs = if ($Params.PSObject.Properties.Name -contains 'createLocalDirs') { [bool]$Params.createLocalDirs } else { $true }
  $passiveMode    = if ($Params.PSObject.Properties.Name -contains 'passiveMode') { [bool]$Params.passiveMode } else { $true }

  # Auto-detect port
  $port = 0
  if ($portStr -and $portStr -match '^\d+$') {
    $port = [int]$portStr
  }
  else {
    $port = switch ($protocol) {
      'ftp'  { 21 }
      'ftps' { if ($ftpsMode -eq 'implicit') { 990 } else { 21 } }
      'sftp' { 22 }
      default { 21 }
    }
  }

  # Determine local destination directory
  $localDir = if ($localPath) {
    $localPath
  }
  elseif ($Cwd -and (Test-Path $Cwd -PathType Container)) {
    $Cwd
  }
  else {
    (Get-Location).Path
  }

  if (-not (Test-Path $localDir -PathType Container)) {
    if ($createLocalDirs) {
      New-Item -Path $localDir -ItemType Directory -Force | Out-Null
    }
    else {
      throw "Local directory does not exist: $localDir"
    }
  }

  # Validation
  Write-XYProgress 0.04 'Validating parameters...'

  if (-not $ftpHost)    { throw 'Host is required. Provide it as a parameter or configure the FTP_HOST secret in the vault.' }
  if (-not $username)   { throw 'Username is required. Provide it as a parameter or configure the FTP_USERNAME secret in the vault.' }
  if (-not $remotePath) { throw 'Remote Path is required.' }

  if ($protocol -eq 'sftp' -and -not $password -and -not $sshKeyPath) {
    throw 'SFTP requires either a password or an SSH key. Provide a password or configure FTP_SSH_KEY_PATH.'
  }
  if ($protocol -ne 'sftp' -and -not $password) {
    throw 'Password is required for FTP/FTPS. Provide it as a parameter or configure the FTP_PASSWORD secret in the vault.'
  }

  # Display configuration
  $authMethod = switch ($protocol) {
    'sftp' { if ($sshKeyPath) { "SSH Key ($sshKeyPath)" } else { 'Password' } }
    default { 'Password' }
  }
  $protocolDesc = switch ($protocol) {
    'ftp'  { 'FTP (Plain)' }
    'ftps' { "FTPS ($( ($ftpsMode.Substring(0,1).ToUpper() + $ftpsMode.Substring(1)) ) TLS)" }
    'sftp' { 'SFTP (SSH)' }
  }
  $downloadModeDesc = switch ($downloadMode) {
    'file' { 'Single File' }
    'folder' { 'Folder (Recursive)' }
    'pattern' { 'Pattern Match' }
    default { $downloadMode }
  }

  Write-XY @{ table = @{
    title  = 'Configuration'
    header = @('Setting', 'Value')
    rows   = @(
      @('Protocol', $protocolDesc),
      @('Host', $ftpHost),
      @('Port', $port),
      @('Username', $username),
      @('Auth Method', $authMethod),
      @('Remote Path', $remotePath),
      @('Local Path', $localDir),
      @('Download Mode', $downloadModeDesc),
      @('If File Exists', ($ifFileExists.Substring(0,1).ToUpper() + $ifFileExists.Substring(1))),
      @('Delete After Download', $(if ($deleteAfter) { 'Yes' } else { 'No' })),
      @('Passive Mode', $(if ($passiveMode) { 'Yes' } else { 'N/A (SFTP)' }))
    )
    caption = ''
  } }

  # Install required modules
  Install-RequiredModules -Protocol $protocol

  # Connect and download
  $results       = [System.Collections.ArrayList]::new()
  $totalSize     = [long]0
  $skippedCount  = 0
  $downloadedCount = 0
  $ftpSession    = $null
  $sftpSession   = $null
  $downloadedFiles = [System.Collections.ArrayList]::new()

  try {
    Write-XYProgress 0.15 "Connecting to ${ftpHost}:${port} via $($protocol.ToUpper())..."

    # Resolve files to download
    $filesToDownload = [System.Collections.ArrayList]::new()

    if ($protocol -eq 'sftp') {
      $sftpSession = New-SFTPConnection -HostName $ftpHost -Port $port -Username $username `
                                        -Password $password -KeyPath $sshKeyPath -KeyPassphrase $sshKeyPassphrase
      $sessionId = $sftpSession.SessionId

      Write-XYProgress 0.20 'Connected via SFTP'

      if ($downloadMode -eq 'file') {
        $null = $filesToDownload.Add(@{ Path = $remotePath; Name = [System.IO.Path]::GetFileName($remotePath); Size = 0 })
      }
      elseif ($downloadMode -eq 'folder') {
        Write-XYProgress 0.22 "Listing remote files in: $remotePath"
        $remoteFiles = Get-SFTPFileList -SessionId $sessionId -RemotePath $remotePath -Recursive $true
        foreach ($file in $remoteFiles) { $null = $filesToDownload.Add($file) }
      }
      elseif ($downloadMode -eq 'pattern') {
        Write-XYProgress 0.22 "Matching remote files: $remotePath"
        $pathDir = [System.IO.Path]::GetDirectoryName($remotePath).Replace('\', '/')
        if ([string]::IsNullOrWhiteSpace($pathDir)) { $pathDir = '/' }
        $pattern = [System.IO.Path]::GetFileName($remotePath)
        $remoteFiles = Get-SFTPFileList -SessionId $sessionId -RemotePath $pathDir -Recursive $false
        foreach ($file in $remoteFiles) {
          if (Test-MatchesGlob -Path $file.Name -Pattern $pattern) {
            $null = $filesToDownload.Add($file)
          }
        }
      }

      if ($filesToDownload.Count -eq 0) { throw "No files found matching: $remotePath" }

      Write-XY @{ table = @{
        title  = 'Files to Download'
        header = @('#', 'File', 'Size')
        rows   = @(
          $filesToDownload | ForEach-Object -Begin { $i = 0 } -Process {
            $i++
            ,@($i, $_.Name, "$( '{0:N0}' -f $_.Size ) bytes")
          }
        )
        caption = "$($filesToDownload.Count) file(s) ready for download"
      } }

      $fileIndex = 0
      foreach ($file in $filesToDownload) {
        $fileIndex++
        $progress = 0.25 + (0.65 * ($fileIndex / $filesToDownload.Count))
        $localFilePath = [System.IO.Path]::Combine($localDir, $file.Name)

        Write-XYProgress $progress "Downloading ($fileIndex/$($filesToDownload.Count)): $($file.Name)"

        if ((Test-Path $localFilePath -PathType Leaf)) {
          if ($ifFileExists -eq 'skip') {
            $skippedCount++
            $null = $results.Add(@{ name = $file.Name; localPath = $localFilePath; size = $file.Size; status = 'skipped' })
            continue
          }
          elseif ($ifFileExists -eq 'error') {
            throw "File already exists locally: $localFilePath"
          }
          elseif ($ifFileExists -eq 'rename') {
            $localFilePath = Get-UniqueFileName -FilePath $localFilePath
          }
        }

        $downloadSize = Get-SFTPSingleFile -SessionId $sessionId -RemoteFile $file.Path -LocalPath $localFilePath
        $totalSize += $downloadSize
        $downloadedCount++
        $null = $results.Add(@{ name = $file.Name; localPath = $localFilePath; size = $downloadSize; status = 'downloaded' })
        $null = $downloadedFiles.Add([System.IO.Path]::GetFileName($localFilePath))

        if ($deleteAfter) {
          Remove-SFTPFile -SessionId $sessionId -RemoteFile $file.Path
        }
      }
    }
    elseif ($protocol -eq 'ftps' -and $ftpsMode -eq 'implicit') {
      $ftpSession = New-ImplicitFTPSSession -HostName $ftpHost -Port $port -Username $username -Password $password

      Write-XYProgress 0.20 'Connected via FTPS (Implicit TLS)'

      if ($downloadMode -eq 'file') {
        $null = $filesToDownload.Add(@{ Path = $remotePath; Name = [System.IO.Path]::GetFileName($remotePath); Size = 0 })
      }
      elseif ($downloadMode -eq 'folder') {
        Write-XYProgress 0.22 "Listing remote files in: $remotePath"
        $remoteFiles = Get-ImplicitFTPSFileList -Session $ftpSession -RemotePath $remotePath -Recursive $true
        foreach ($file in $remoteFiles) { $null = $filesToDownload.Add($file) }
      }
      elseif ($downloadMode -eq 'pattern') {
        Write-XYProgress 0.22 "Matching remote files: $remotePath"
        $pathDir = [System.IO.Path]::GetDirectoryName($remotePath).Replace('\', '/')
        if ([string]::IsNullOrWhiteSpace($pathDir)) { $pathDir = '/' }
        $pattern = [System.IO.Path]::GetFileName($remotePath)
        $remoteFiles = Get-ImplicitFTPSFileList -Session $ftpSession -RemotePath $pathDir -Recursive $false
        foreach ($file in $remoteFiles) {
          if (Test-MatchesGlob -Path $file.Name -Pattern $pattern) {
            $null = $filesToDownload.Add($file)
          }
        }
      }

      if ($filesToDownload.Count -eq 0) { throw "No files found matching: $remotePath" }

      Write-XY @{ table = @{
        title  = 'Files to Download'
        header = @('#', 'File', 'Size')
        rows   = @(
          $filesToDownload | ForEach-Object -Begin { $i = 0 } -Process {
            $i++
            ,@($i, $_.Name, "$( '{0:N0}' -f $_.Size ) bytes")
          }
        )
        caption = "$($filesToDownload.Count) file(s) ready for download"
      } }

      $fileIndex = 0
      foreach ($file in $filesToDownload) {
        $fileIndex++
        $progress = 0.25 + (0.65 * ($fileIndex / $filesToDownload.Count))
        $localFilePath = [System.IO.Path]::Combine($localDir, $file.Name)

        Write-XYProgress $progress "Downloading ($fileIndex/$($filesToDownload.Count)): $($file.Name)"

        if ((Test-Path $localFilePath -PathType Leaf)) {
          if ($ifFileExists -eq 'skip') {
            $skippedCount++
            $null = $results.Add(@{ name = $file.Name; localPath = $localFilePath; size = $file.Size; status = 'skipped' })
            continue
          }
          elseif ($ifFileExists -eq 'error') {
            throw "File already exists locally: $localFilePath"
          }
          elseif ($ifFileExists -eq 'rename') {
            $localFilePath = Get-UniqueFileName -FilePath $localFilePath
          }
        }

        $downloadSize = Get-ImplicitFTPSSingleFile -Session $ftpSession -RemoteFile $file.Path -LocalPath $localFilePath
        $totalSize += $downloadSize
        $downloadedCount++
        $null = $results.Add(@{ name = $file.Name; localPath = $localFilePath; size = $downloadSize; status = 'downloaded' })
        $null = $downloadedFiles.Add([System.IO.Path]::GetFileName($localFilePath))

        if ($deleteAfter) {
          Remove-ImplicitFTPSFile -Session $ftpSession -RemoteFile $file.Path
        }
      }
    }
    else {
      # FTP / FTPS Explicit
      $enableSsl  = ($protocol -eq 'ftps')
      $credential = [System.Net.NetworkCredential]::new($username, $password)
      $baseUrl    = Get-FTPBaseUrl -HostName $ftpHost -Port $port

      Write-XYProgress 0.20 "Connected via $($protocol.ToUpper())$(if ($enableSsl) { ' (Explicit TLS)' } else { '' })"

      if ($downloadMode -eq 'file') {
        $null = $filesToDownload.Add(@{ Path = $remotePath; Name = [System.IO.Path]::GetFileName($remotePath); Size = 0 })
      }
      elseif ($downloadMode -eq 'folder') {
        Write-XYProgress 0.22 "Listing remote files in: $remotePath"
        $remoteFiles = Get-FTPFileList -BaseUrl $baseUrl -RemotePath $remotePath -Credential $credential `
                                       -EnableSsl $enableSsl -PassiveMode $passiveMode -Recursive $true
        foreach ($file in $remoteFiles) { $null = $filesToDownload.Add($file) }
      }
      elseif ($downloadMode -eq 'pattern') {
        Write-XYProgress 0.22 "Matching remote files: $remotePath"
        $pathDir = [System.IO.Path]::GetDirectoryName($remotePath).Replace('\', '/')
        if ([string]::IsNullOrWhiteSpace($pathDir)) { $pathDir = '/' }
        $pattern = [System.IO.Path]::GetFileName($remotePath)
        $remoteFiles = Get-FTPFileList -BaseUrl $baseUrl -RemotePath $pathDir -Credential $credential `
                                       -EnableSsl $enableSsl -PassiveMode $passiveMode -Recursive $false
        foreach ($file in $remoteFiles) {
          if (Test-MatchesGlob -Path $file.Name -Pattern $pattern) {
            $null = $filesToDownload.Add($file)
          }
        }
      }

      if ($filesToDownload.Count -eq 0) { throw "No files found matching: $remotePath" }

      Write-XY @{ table = @{
        title  = 'Files to Download'
        header = @('#', 'File', 'Size')
        rows   = @(
          $filesToDownload | ForEach-Object -Begin { $i = 0 } -Process {
            $i++
            ,@($i, $_.Name, "$( '{0:N0}' -f $_.Size ) bytes")
          }
        )
        caption = "$($filesToDownload.Count) file(s) ready for download"
      } }

      $fileIndex = 0
      foreach ($file in $filesToDownload) {
        $fileIndex++
        $progress = 0.25 + (0.65 * ($fileIndex / $filesToDownload.Count))
        $localFilePath = [System.IO.Path]::Combine($localDir, $file.Name)

        Write-XYProgress $progress "Downloading ($fileIndex/$($filesToDownload.Count)): $($file.Name)"

        if ((Test-Path $localFilePath -PathType Leaf)) {
          if ($ifFileExists -eq 'skip') {
            $skippedCount++
            $null = $results.Add(@{ name = $file.Name; localPath = $localFilePath; size = $file.Size; status = 'skipped' })
            continue
          }
          elseif ($ifFileExists -eq 'error') {
            throw "File already exists locally: $localFilePath"
          }
          elseif ($ifFileExists -eq 'rename') {
            $localFilePath = Get-UniqueFileName -FilePath $localFilePath
          }
        }

        $downloadSize = Get-FTPSingleFile -BaseUrl $baseUrl -RemoteFile $file.Path -LocalPath $localFilePath `
                                         -Credential $credential -EnableSsl $enableSsl -PassiveMode $passiveMode
        $totalSize += $downloadSize
        $downloadedCount++
        $null = $results.Add(@{ name = $file.Name; localPath = $localFilePath; size = $downloadSize; status = 'downloaded' })
        $null = $downloadedFiles.Add([System.IO.Path]::GetFileName($localFilePath))

        if ($deleteAfter) {
          Remove-FTPFile -BaseUrl $baseUrl -RemoteFile $file.Path -Credential $credential `
                         -EnableSsl $enableSsl -PassiveMode $passiveMode
        }
      }
    }

    # Display results
    Write-XYProgress 0.95 'Download complete'

    $resultRows = @($results | ForEach-Object -Begin { $i = 0 } -Process {
      $i++
      $statusIcon = switch ($_.status) { 'downloaded' { 'Downloaded' }; 'skipped' { 'Skipped' }; default { $_.status } }
      ,@($i, $_.name, "$( '{0:N0}' -f $_.size ) bytes", $statusIcon)
    })

    Write-XY @{ table = @{
      title   = 'Download Results'
      header  = @('#', 'File', 'Size', 'Status')
      rows    = $resultRows
      caption = "$downloadedCount downloaded, $skippedCount skipped, $( '{0:N0}' -f $totalSize ) bytes total"
    } }

    # Build output data
    return [pscustomobject]@{
      tool           = 'ftpDownload'
      success        = $true
      protocol       = $protocol
      host           = $ftpHost
      port           = $port
      remotePath     = $remotePath
      localPath      = $localDir
      files          = @($results)
      downloadedFiles = @($downloadedFiles.ToArray())
      totalFiles     = $downloadedCount
      totalSize      = $totalSize
      skippedFiles   = $skippedCount
      deletedRemote  = $deleteAfter
      timestamp      = [datetime]::UtcNow.ToString('o')
    }
  }
  catch {
    $phase = switch -Regex ($_.Exception.Message) {
      'resolv|DNS|refused|timeout|unreachable|connect' { 'Connection'; break }
      'auth|login|credential|key.*invalid|passphrase'  { 'Authentication'; break }
      'permission|denied|550|553'                      { 'Permission'; break }
      'SSL|TLS|certificate|handshake'                  { 'Protocol'; break }
      default                                          { 'Transfer' }
    }

    $errorMsg = Format-TransferError -ErrorRecord $_ -Phase $phase -Protocol $protocol
    throw $errorMsg
  }
  finally {
    if ($ftpSession)  { Close-ImplicitFTPSSession -Session $ftpSession }
    if ($sftpSession) { Close-SFTPConnection -SessionId $sftpSession.SessionId }
  }
}

#endregion

#region Main Entry Point

try {
  $job    = Read-JobFromStdin
  $Params = $job.params

  $Cwd = if ($job.PSObject.Properties.Name -contains 'cwd') { $job.cwd } else { $null }

  if ($Cwd -and (Test-Path $Cwd -PathType Container)) { Set-Location $Cwd }

  $result = Invoke-FTPDownload -Params $Params -Cwd $Cwd
  Write-XYSuccess -Data $result -Files $result.downloadedFiles -Description "Downloaded $($result.totalFiles) file(s) via $($result.protocol.ToUpper()) from $($result.host)"
  exit 0
}
catch {
  Write-XYError -Code 1 -Description $_.Exception.Message
  exit 1
}

#endregion
