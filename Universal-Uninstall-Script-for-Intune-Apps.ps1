function Uninstall-Programs {
  [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
  param(
    [Parameter(Mandatory)]
    [string]$Name,                       # Wildcards allowed, e.g. 'Adobe*'

    [switch]$Silent,                     # Adds quiet flags for MSI (msiexec) only

    [int[]]$IncludeExitCodes = @(0,3010,1641), # Treat as success (MSI success/reboot)
                                               # Add 19 for Chrome if desired
    [switch]$StopRunningProcesses        # Best-effort: stop similarly named processes
  )

  $ErrorActionPreference = 'Stop'

  $roots = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
  )

  function Get-UninstallEntries {
    param([string]$Pattern)
    foreach ($root in $roots) {
      Get-ItemProperty -Path $root -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -and ($_.DisplayName -like $Pattern) } |
        ForEach-Object {
          $installLoc = $_.InstallLocation
          $systemLevel = $installLoc -and ($installLoc -like '*Program Files*')
          [PSCustomObject]@{
            DisplayName          = $_.DisplayName
            Publisher            = $_.Publisher
            DisplayVersion       = $_.DisplayVersion
            QuietUninstallString = $_.QuietUninstallString
            UninstallString      = $_.UninstallString
            InstallLocation      = $_.InstallLocation
            Scope                = if ($systemLevel) { 'System' } else { 'User' }
          }
        }
    }
  }

  function Start-Cmd {
    param([string]$CmdLine)
    if ($CmdLine -match '^\s*"([^"]+)"\s*(.*)$') {
      $exe = $matches[1]; $args = $matches[2]
      return Start-Process -FilePath $exe -ArgumentList $args -Wait -PassThru
    } elseif ($CmdLine -match '^\s*([^\s]+)\s*(.*)$') {
      $exe = $matches[1]; $args = $matches[2]
      return Start-Process -FilePath $exe -ArgumentList $args -Wait -PassThru
    } else {
      return Start-Process -FilePath 'cmd.exe' -ArgumentList "/c $CmdLine" -Wait -PassThru
    }
  }

  $targets = Get-UninstallEntries -Pattern $Name | Sort-Object DisplayName -Unique

  if (-not $targets) {
    Write-Output "No products found matching '$Name'."
    return
  }

  Write-Output "Found:"
  $targets | Format-Table DisplayName, DisplayVersion, Publisher, Scope -AutoSize

  if ($StopRunningProcesses) {
    $procNames = $targets.DisplayName |
                 ForEach-Object { ($_ -replace '[^A-Za-z0-9]', '') } |
                 ForEach-Object { $_.ToLower() } |
                 Select-Object -Unique
    foreach ($p in (Get-Process -ErrorAction SilentlyContinue)) {
      $pn = ($p.ProcessName -replace '[^A-Za-z0-9]', '').ToLower()
      if ($procNames -contains $pn) {
        try { $p | Stop-Process -Force -ErrorAction Stop } catch {}
      }
    }
  }

  $success = @()
  $fail    = @()

  foreach ($t in $targets) {
    # Prefer vendor-provided quiet command if present
    $cmd = if ($t.QuietUninstallString) { $t.QuietUninstallString } else { $t.UninstallString }

    if (-not $cmd) {
      $fail += "$($t.DisplayName) (no uninstall string)"
      Write-Warning "No uninstall command found for $($t.DisplayName)."
      continue
    }

    # --- MSI FIX: force uninstall, not repair/maintenance ---
    if ($cmd -match '(?i)\bmsiexec(\.exe)?\b') {
      # Replace any /I (install/maintain) or /F... (repair) with /x (uninstall)
      $cmd = $cmd `
        -replace '(?i)(?<=\s)/i(\b|$)', '/x' `
        -replace '(?i)(?<=\s)/f[a-z]*', '/x' `
        -replace '(?i)\bREPAIR=ALL\b', '' `
        -replace '(?i)\bADDLOCAL=.*?\b', ''

      if ($Silent) {
        if ($cmd -notmatch '(?i)\s/qn(\b|$)')        { $cmd += ' /qn' }
        if ($cmd -notmatch '(?i)\s/norestart(\b|$)') { $cmd += ' /norestart' }
      }
    } else {
      # Non-MSI: do not guess silent flags; vendors differ.
      # (If you know the installer type, add flags when calling the function.)
    }
    # --- end MSI FIX ---

    if ($PSCmdlet.ShouldProcess($t.DisplayName, "Uninstall")) {
      Write-Output "Uninstalling: $($t.DisplayName) [$($t.Scope)]"
      try {
        $proc = Start-Cmd -CmdLine $cmd
        $rc = $proc.ExitCode

        if ($IncludeExitCodes -contains $rc) {
          $success += "$($t.DisplayName) (rc=$rc)"
          Write-Output "Success: $($t.DisplayName) (rc=$rc)"
        } else {
          $fail += "$($t.DisplayName) (rc=$rc)"
          Write-Warning "Failed: $($t.DisplayName) with exit code $rc"
        }
      } catch {
        $fail += "$($t.DisplayName) ($($_.Exception.Message))"
        Write-Warning "Error uninstalling $($t.DisplayName): $($_.Exception.Message)"
      }
    }
  }

  Write-Output "----- Summary -----"
  if ($success) { Write-Output ("Uninstalled: " + ($success -join ', ')) }
  if ($fail)    { Write-Output ("Failures: "   + ($fail   -join ', ')) } else { Write-Output "No failures reported." }
}
