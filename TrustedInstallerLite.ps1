#region TI HELPER
function TrustedInstaller {
    [CmdletBinding(SupportsShouldProcess, PositionalBinding = $false)]
    param(
        [Parameter(Mandatory, Position = 0)]
        [object]$Command,

        [Parameter(Position = 1, ValueFromRemainingArguments)]
        [object[]]$ArgumentList
    )

    $restoreDisabled = $false
    $tiSvc = Get-Service TrustedInstaller -EA 0
    if ($tiSvc -and $tiSvc.Status -ne 'Running') {
        # A disabled service can't be started; flip to Manual and restore it in the finally block
        if ($tiSvc.StartType -eq 'Disabled') {
            Set-Service TrustedInstaller -StartupType Manual -EA 0
            $restoreDisabled = $true
        }
        Start-Service TrustedInstaller -EA 0
        # Wait for the TrustedInstaller process to actually spawn before we try to open its token
        $tiDeadline = (Get-Date).AddSeconds(5)
        while (!(Get-Process TrustedInstaller -EA 0) -and (Get-Date) -lt $tiDeadline) {
            Start-Sleep -Milliseconds 100
        }
    }
    if (!$global:TI_Lite) {
        $I = [IntPtr]; $U = [uint32]; $N = [int32]; $B = [bool]; $IR = $I.MakeByRefType(); $LR = [int64].MakeByRefType()
        $tb = [System.Reflection.Emit.AssemblyBuilder]::DefineDynamicAssembly([System.Reflection.AssemblyName]::new('TI_Lite'), 1).DefineDynamicModule('TI_Lite').DefineType('TI_Lite', 'Public,Class')
        $k = 'kernel32'; $a = 'advapi32'
        $dc = [Runtime.InteropServices.DllImportAttribute].GetConstructor(@([string]))
        $sf = [Runtime.InteropServices.DllImportAttribute].GetField('SetLastError')
        $cf = [Runtime.InteropServices.DllImportAttribute].GetField('CharSet')
        function add($d, $e, $m, $r, $p) {
            $mb = $tb.('DefinePInvoke' + 'Method')($m, $d, $e, 8214, 1, $r, $p, 1, 3)
            $mb.SetImplementationFlags(128)
            $mb.SetCustomAttribute((New-Object Reflection.Emit.CustomAttributeBuilder($dc, @($d), [Reflection.FieldInfo[]]@($sf, $cf), @($true, 3))))
        }
        add $k 'OpenProcess' M1 $I @($U, $B, $N)
        add $a 'OpenProcessToken' M2 $B @($I, $U, $IR)
        add $a 'DuplicateTokenEx' M3 $B @($I, $U, $I, $N, $N, $IR)
        add $a 'SetThreadToken' M4 $B @($IR, $I)
        add $a 'RevertToSelf' M5 $B @()
        add $k 'CloseHandle' M6 $B @($I)
        add $a 'LookupPrivilegeValueW' M7 $B @($I, $I, $LR)
        add $a 'AdjustTokenPrivileges' M8 $B @($I, $B, $I, $U, $I, $I)
        add $k 'GetCurrentProcess' M9 $I @()
        add $k 'GetCurrentThread' M10 $I @()
        $global:TI_Lite = $tb.CreateType()
    }

    $hTok = [IntPtr]::Zero
    if ($global:TI_Lite::M2($global:TI_Lite::M9(), 40, [ref]$hTok)) {
        $luid = [int64]0
        $sp = [Runtime.InteropServices.Marshal]::StringToHGlobalUni('SeDebugPrivilege')
        if ($global:TI_Lite::M7([IntPtr]::Zero, $sp, [ref]$luid)) {
            $tp = [Runtime.InteropServices.Marshal]::AllocHGlobal(16)
            [Runtime.InteropServices.Marshal]::WriteInt32($tp, 1)
            [Runtime.InteropServices.Marshal]::WriteInt64([IntPtr]($tp.ToInt64() + 4), $luid)
            [Runtime.InteropServices.Marshal]::WriteInt32([IntPtr]($tp.ToInt64() + 12), 2)
            $global:TI_Lite::M8($hTok, $false, $tp, 0, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null
            [Runtime.InteropServices.Marshal]::FreeHGlobal($tp)
        }
        [Runtime.InteropServices.Marshal]::FreeHGlobal($sp)
        $global:TI_Lite::M6($hTok) | Out-Null
    }

    $hWl = [IntPtr]::Zero; $hWlTok = [IntPtr]::Zero; $hWlDup = [IntPtr]::Zero
    $hTi = [IntPtr]::Zero; $hTiTok = [IntPtr]::Zero; $hTiDup = [IntPtr]::Zero
    $needRevert = $false
    $haveTi = $false

    try {
        $wlPid = ([Diagnostics.Process]::GetProcessesByName('winlogon') | Select-Object -First 1).Id
        if ($wlPid) {
            $hWl = $global:TI_Lite::M1(1024, $false, $wlPid)
            if ($hWl -ne [IntPtr]::Zero -and $global:TI_Lite::M2($hWl, 10, [ref]$hWlTok) -and $global:TI_Lite::M3($hWlTok, 0x000F01FF, [IntPtr]::Zero, 2, 2, [ref]$hWlDup)) {
                $ct = $global:TI_Lite::M10()
                if ($global:TI_Lite::M4([ref]$ct, $hWlDup)) { $needRevert = $true }
            }
        }

        $p = Get-Process TrustedInstaller -EA 0
        if ($p) {
            $hTi = $global:TI_Lite::M1(1024, $false, $p.Id)
            if ($hTi -ne [IntPtr]::Zero -and $global:TI_Lite::M2($hTi, 10, [ref]$hTiTok) -and $global:TI_Lite::M3($hTiTok, 0x000F01FF, [IntPtr]::Zero, 2, 2, [ref]$hTiDup)) {
                $ct = $global:TI_Lite::M10()
                if ($global:TI_Lite::M4([ref]$ct, $hTiDup)) { $needRevert = $true; $haveTi = $true }
            }
        }

        if (-not $haveTi) {
            $tiWarn = "Failed to acquire TrustedInstaller token; running as $([Security.Principal.WindowsIdentity]::GetCurrent().Name)."
            if (Get-Command Write-Log -EA 0) { Write-Log $tiWarn WARN } else { Write-Warning $tiWarn }
        }

        if ($Command) {
            if ($Command -is [scriptblock]) {
                & $Command @ArgumentList
            }
            else {
                $txt = [string]$Command
                if ($txt -match '(?i)\.ps1$' -and (Test-Path -LiteralPath $txt -PathType Leaf)) {
                    & (Resolve-Path -LiteralPath $txt).ProviderPath @ArgumentList
                }
                else {
                    if ($ArgumentList -and $ArgumentList.Count -gt 0) {
                        $txt = (@($txt) + ($ArgumentList | ForEach-Object { [string]$_ })) -join ' '
                    }
                    & ([scriptblock]::Create($txt))
                }
            }
        }
        else {
            throw "No command specified for TrustedInstaller."
        }
    }
    finally {
        if ($needRevert) { $global:TI_Lite::M5() | Out-Null }
        foreach ($h in @($hTiDup, $hTiTok, $hTi, $hWlDup, $hWlTok, $hWl)) {
            if ($h -ne [IntPtr]::Zero) { $global:TI_Lite::M6($h) | Out-Null }
        }
        if ($restoreDisabled) { Set-Service TrustedInstaller -StartupType Disabled -EA 0 }
    }
}
#endregion
# SIG # Begin signature block
# MIIFhgYJKoZIhvcNAQcCoIIFdzCCBXMCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCB6LdrWUo+cIf4S
# 8dWXArCXEzqf18qPx79kOqaDHWu93KCCAwAwggL8MIIB5KADAgECAhBmxEuaKxK9
# q0DArcSbBV1VMA0GCSqGSIb3DQEBCwUAMBYxFDASBgNVBAMMC1Bvd2Vyc2hlbGxv
# MB4XDTI2MDYxNjAxMTQ0NFoXDTI3MDYxNjAxMzQ0NFowFjEUMBIGA1UEAwwLUG93
# ZXJzaGVsbG8wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC4P3efhkwC
# YF+ucOGgyUUs6aobEG+quoNdzUSbDNLkjizbzsKZ45P+fmLm91dgoEXN0zYVRg4u
# nLALU54tDXv5iNLUrAR51qMiyPKcHGovt13zCKcd4GZ3KzhVRBxwMi0vreb7zM6I
# 2aOXuw92j2ZiGSYBeajWSVfCHt3SLjjQLrHOPKUzf4bH8JlbFO1Lf5UeRrOLb/E2
# yO9Z/a+urVT4GdLaS22ID/v/wUsg/2o3JcRr1tujbAFiBjX6K01EH/HIGC9/mLKH
# N3RbCxzoa5GTgTsNTGp9qtMM1FGzLqoRRFPmi/5j4XShLTE2gCaWgBjYS58G+b25
# M9+vp49h7qxdAgMBAAGjRjBEMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggr
# BgEFBQcDAzAdBgNVHQ4EFgQURhglG42HEzSj03yo+4bGFFMgWXEwDQYJKoZIhvcN
# AQELBQADggEBADW1paY2bJVsi9ecx7RAZf9IAY52M8gNyePAks2rmnIMfmIARnR3
# RGbwMJ7zUGjJmwgbZP80COfriOzl+1tnDx5NZSxtNmcF5xF0qv9nwpoO8BkO5ANM
# ecTXlTG9Fj9DK83y8yUL2I9BLTZwUt2KkgJpemPompEvkI3oX5CGskNQX1QgiQ9P
# 8Zw1GasgR4uEj+Wpce7ELcEsNZ84P2u/97iMPndVtqeBG1PbWSSgyRc2RrpsU1Cv
# +gy2oiBGfXUdq4GbPi2VHKtKgLV0vKxMzuaXhOLa/MS7CbbdmjmF+jEexEzZSwZB
# KHA+yIAC4g1aLjky4kDzXRT1cbQgNGMsMp8xggHcMIIB2AIBATAqMBYxFDASBgNV
# BAMMC1Bvd2Vyc2hlbGxvAhBmxEuaKxK9q0DArcSbBV1VMA0GCWCGSAFlAwQCAQUA
# oIGEMBgGCisGAQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisG
# AQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcN
# AQkEMSIEIKUmSF6WNWVoBafiLWdydswqAzS4ySQ3CdzwEEcZ/160MA0GCSqGSIb3
# DQEBAQUABIIBACPM0t30+EA6hgoN5GzeEjxXqBtyuRq5JpgVPTo6/CNJWh8Le2mN
# l1Mr3SWByIpdZFkcRc5/QnlBi2/qLwJeRHuT3Xdd0hg8fDG9WQxJYffRd4bX+3RG
# BfLBy+Kg4WD8ElsxTmvgzdA7AKFiCjldtrF8TPM3yW+oCG5FMIdAggJvLOIxTNgO
# EEGOE7JiGyzJdI3FHpnq/eJM0QU9ykZzHNhNHNq7VvqlzwFG2bIf7iUkeUUrub3q
# BtSW6RDWp9VHygdT58hPV6jpzPN1RpoanCossSq9ZAbPCQzrhU6vc3n6tRM95uXh
# xNOeC0E2cV61uVg1GG6xVHNiZ2sdztdwxnY=
# SIG # End signature block
