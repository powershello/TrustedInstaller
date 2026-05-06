function TrustedInstaller {
    [CmdletBinding(PositionalBinding = $false, SupportsShouldProcess = $true)]
    param(
        [Alias('ts')]
        [ValidateRange(0, 86400)]
        [int]$TimeoutSec = 120,

        [Alias('ps')]
        [switch]$PowerShell,

        [Parameter(Position = 0, ValueFromRemainingArguments = $true)]
        [string[]]$Command
    )


    If (-not([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
        Write-Error 'TrustedInstaller requires Administrator privileges. Please run this script as Administrator.'
        return
    }

    function Initialize-NativeBindings {
        if ($global:TI_NativeAPI) {
            if ($global:TI_NativeAPI -is [type] -and $global:TI_NativeAPI.GetMethod('GetLastError')) {
                return $true
            }
            $global:TI_NativeAPI = $null
        }
        
        try {
            $AssemblyNameString = 'System.Management.Infrastructure.Win32Interop'
            $AssemblyName = New-Object System.Reflection.AssemblyName($AssemblyNameString)
            $DynamicAssembly = if ([AppDomain]::CurrentDomain.GetType().GetMethod('DefineDynamicAssembly', [type[]]@([System.Reflection.AssemblyName], [System.Reflection.Emit.AssemblyBuilderAccess]))) {
                [AppDomain]::CurrentDomain.DefineDynamicAssembly($AssemblyName, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
            }
            else {
                [System.Reflection.Emit.AssemblyBuilder]::DefineDynamicAssembly($AssemblyName, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
            }
            $DynamicModule = if ($DynamicAssembly.GetType().GetMethod('DefineDynamicModule', [type[]]@([string], [bool]))) {
                $DynamicAssembly.DefineDynamicModule($AssemblyNameString, $false)
            }
            else {
                $DynamicAssembly.DefineDynamicModule($AssemblyNameString)
            }
            $TypeBuilder = $DynamicModule.DefineType('NativeMethods', 'Public, Class')

            function Register-Win32Api {
                param([String]$DllName, [String]$MethodName, [Type]$ReturnType, [Type[]]$ParameterTypes, [switch]$IsAnsi)
                
                $MethodAttributes = [System.Reflection.MethodAttributes]::Public -bor [System.Reflection.MethodAttributes]::Static -bor [System.Reflection.MethodAttributes]::PinvokeImpl
                $CallingConvention = [System.Reflection.CallingConventions]::Standard
                
                $CharSetValue = if ($IsAnsi) { [System.Runtime.InteropServices.CharSet]::Ansi } else { [System.Runtime.InteropServices.CharSet]::Unicode }
                $MethodBuilder = $TypeBuilder.DefinePInvokeMethod($MethodName, $DllName, $MethodAttributes, $CallingConvention, $ReturnType, $ParameterTypes, [System.Runtime.InteropServices.CallingConvention]::Winapi, $CharSetValue)
                
                $MethodBuilder.SetImplementationFlags([System.Reflection.MethodImplAttributes]::PreserveSig)
                
                $DllImportConstructor = [System.Runtime.InteropServices.DllImportAttribute].GetConstructor(@([String]))
                $SetLastErrorField = [System.Runtime.InteropServices.DllImportAttribute].GetField('SetLastError')
                $CharSetField = [System.Runtime.InteropServices.DllImportAttribute].GetField('CharSet')
                $CaptureLastError = $MethodName -ne 'GetLastError'
                
                $DllImportAttribute = New-Object System.Reflection.Emit.CustomAttributeBuilder(
                    $DllImportConstructor, @($DllName),
                    [System.Reflection.FieldInfo[]]@($SetLastErrorField, $CharSetField),
                    [Object[]]@($CaptureLastError, $CharSetValue)
                )
                $MethodBuilder.SetCustomAttribute($DllImportAttribute)
            }

            $TypeIntPtr = [IntPtr]; $TypeBool = [Bool]; $TypeUInt32 = [UInt32]; $TypeInt32 = [Int32]; $TypeVoid = [void]
            
            $TypeIntPtrRef = $TypeIntPtr.MakeByRefType()
            $TypeUInt32Ref = $TypeUInt32.MakeByRefType()
            $TypeInt32Ref = $TypeInt32.MakeByRefType()
            $TypeInt64Ref = [Int64].MakeByRefType()

            @(
                , ('kernel32.dll', 'OpenProcess', $TypeIntPtr, @($TypeUInt32, $TypeBool, $TypeInt32), $false)
                , ('kernel32.dll', 'CloseHandle', $TypeBool, @($TypeIntPtr), $false)
                , ('kernel32.dll', 'GetLastError', $TypeUInt32, @(), $false)
                , ('kernel32.dll', 'InitializeProcThreadAttributeList', $TypeBool, @($TypeIntPtr, $TypeInt32, $TypeUInt32, $TypeIntPtrRef), $false)
                , ('kernel32.dll', 'UpdateProcThreadAttribute', $TypeBool, @($TypeIntPtr, $TypeUInt32, $TypeIntPtr, $TypeIntPtr, $TypeIntPtr, $TypeIntPtr, $TypeIntPtr), $false)
                , ('kernel32.dll', 'DeleteProcThreadAttributeList', $TypeVoid, @($TypeIntPtr), $false)
                , ('kernel32.dll', 'CreateProcessW', $TypeBool, @($TypeIntPtr, $TypeIntPtr, $TypeIntPtr, $TypeIntPtr, $TypeBool, $TypeUInt32, $TypeIntPtr, $TypeIntPtr, $TypeIntPtr, $TypeIntPtr), $false)
                , ('kernel32.dll', 'WaitForSingleObject', $TypeUInt32, @($TypeIntPtr, $TypeUInt32), $false)
                , ('kernel32.dll', 'GetExitCodeProcess', $TypeBool, @($TypeIntPtr, $TypeInt32Ref), $false)
                , ('kernel32.dll', 'TerminateProcess', $TypeBool, @($TypeIntPtr, $TypeUInt32), $false)
                , ('kernel32.dll', 'PeekNamedPipe', $TypeBool, @($TypeIntPtr, $TypeIntPtr, $TypeUInt32, $TypeIntPtr, $TypeUInt32Ref, $TypeIntPtr), $false)
                , ('kernel32.dll', 'ResumeThread', $TypeUInt32, @($TypeIntPtr), $false)
                , ('advapi32.dll', 'OpenProcessToken', $TypeBool, @($TypeIntPtr, $TypeUInt32, $TypeIntPtrRef), $false)
                , ('advapi32.dll', 'DuplicateTokenEx', $TypeBool, @($TypeIntPtr, $TypeUInt32, $TypeIntPtr, $TypeInt32, $TypeInt32, $TypeIntPtrRef), $false)
                , ('advapi32.dll', 'SetThreadToken', $TypeBool, @($TypeIntPtrRef, $TypeIntPtr), $false)
                , ('advapi32.dll', 'RevertToSelf', $TypeBool, @(), $false)
                , ('advapi32.dll', 'LookupPrivilegeValueW', $TypeBool, @($TypeIntPtr, $TypeIntPtr, $TypeInt64Ref), $false)
                , ('advapi32.dll', 'AdjustTokenPrivileges', $TypeBool, @($TypeIntPtr, $TypeBool, $TypeIntPtr, $TypeUInt32, $TypeIntPtr, $TypeIntPtr), $false)
                , ('advapi32.dll', 'OpenSCManagerW', $TypeIntPtr, @($TypeIntPtr, $TypeIntPtr, $TypeUInt32), $false)
                , ('advapi32.dll', 'OpenServiceW', $TypeIntPtr, @($TypeIntPtr, $TypeIntPtr, $TypeUInt32), $false)
                , ('advapi32.dll', 'QueryServiceStatusEx', $TypeBool, @($TypeIntPtr, $TypeInt32, $TypeIntPtr, $TypeUInt32, $TypeUInt32Ref), $false)
                , ('advapi32.dll', 'CloseServiceHandle', $TypeBool, @($TypeIntPtr), $false)
                , ('kernel32.dll', 'CreateJobObjectW', $TypeIntPtr, @($TypeIntPtr, $TypeIntPtr), $false)
                , ('kernel32.dll', 'CreateIoCompletionPort', $TypeIntPtr, @($TypeIntPtr, $TypeIntPtr, $TypeIntPtr, $TypeUInt32), $false)
                , ('kernel32.dll', 'GetQueuedCompletionStatus', $TypeBool, @($TypeIntPtr, $TypeUInt32Ref, $TypeIntPtrRef, $TypeIntPtrRef, $TypeUInt32), $false)
                , ('kernel32.dll', 'SetInformationJobObject', $TypeBool, @($TypeIntPtr, $TypeInt32, $TypeIntPtr, $TypeUInt32), $false)
                , ('kernel32.dll', 'AssignProcessToJobObject', $TypeBool, @($TypeIntPtr, $TypeIntPtr), $false)
                , ('kernel32.dll', 'GetEnvironmentStringsW', $TypeIntPtr, @(), $false)
                , ('kernel32.dll', 'FreeEnvironmentStringsW', $TypeBool, @($TypeIntPtr), $false)
                , ('kernel32.dll', 'GetCurrentProcess', $TypeIntPtr, @(), $false)
                , ('kernel32.dll', 'GetCurrentThread', $TypeIntPtr, @(), $false)
            ) | ForEach-Object { 
                Register-Win32Api -DllName $_[0] -MethodName $_[1] -ReturnType $_[2] -ParameterTypes $_[3] -IsAnsi:$_[4] 
            }

            $global:TI_NativeAPI = $TypeBuilder.CreateType()
            return $true
        }
        catch {
            Write-Warning "Failed to initialize native bindings: $_"
            return $false
        }
    }

    function Close-SafeHandle {
        param([ref]$Handle)
        if ($Handle.Value -ne [IntPtr]::Zero) {
            $null = $global:TI_NativeAPI::CloseHandle($Handle.Value)
            $Handle.Value = [IntPtr]::Zero
        }
    }

    function Clear-SafeHGlobal {
        param([ref]$Ptr)
        if ($Ptr.Value -ne [IntPtr]::Zero) {
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($Ptr.Value)
            $Ptr.Value = [IntPtr]::Zero
        }
    }

    function Format-Win32Error {
        param(
            [string]$ApiName,
            [int]$ErrorCode
        )

        $Message = try {
            ([ComponentModel.Win32Exception]::new($ErrorCode)).Message
        }
        catch {
            'Unknown error'
        }

        return "$ApiName failed with Win32 error $ErrorCode ($Message)."
    }

    function Join-CmdLiteralArguments {
        param([string[]]$Tokens)
        if (-not $Tokens -or $Tokens.Count -eq 0) { return '' }

        function ConvertTo-CmdLiteralArgument {
            param(
                [string]$Token,
                [bool]$IsCommandName
            )

            $NeedsQuotes = $Token -eq '' -or $Token -match '[\s"&|()!<>\^]'
            if (-not $NeedsQuotes) {
                return ($Token -replace '%', '^%')
            }

            if ($IsCommandName) {
                $inner = ($Token -replace '"', '""') -replace '%', '%%'
                return "`"$inner`""
            }

            $escaped = $Token -replace '\^', '^^'
            $escaped = $escaped -replace '%', '^%'
            $escaped = $escaped -replace '"', '""'
            $escaped = $escaped -replace '([&|()<>])', '^$1'
            return '^"' + $escaped + '^"'
        }

        if ($Tokens.Count -eq 1) {
            return (ConvertTo-CmdLiteralArgument -Token $Tokens[0] -IsCommandName $true)
        }
        $formatted = for ($ArgumentIndex = 0; $ArgumentIndex -lt $Tokens.Count; $ArgumentIndex++) {
            ConvertTo-CmdLiteralArgument -Token $Tokens[$ArgumentIndex] -IsCommandName ($ArgumentIndex -eq 0)
        }
        return ($formatted -join ' ')
    }

    function Get-ServiceProcessId {
        $ServiceManagerHandle = $global:TI_NativeAPI::OpenSCManagerW([IntPtr]::Zero, [IntPtr]::Zero, 0x0001)
        if ($ServiceManagerHandle -eq [IntPtr]::Zero) {
            return 0
        }

        try {
            $ServiceNamePtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni('TrustedInstaller')
            $ServiceHandle = $global:TI_NativeAPI::OpenServiceW($ServiceManagerHandle, $ServiceNamePtr, 0x0004)
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ServiceNamePtr)

            if ($ServiceHandle -eq [IntPtr]::Zero) {
                return 0
            }

            try {
                $StatusBuffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(36)
                $BytesNeeded = [UInt32]0
                $TargetPid = 0
                
                if ($global:TI_NativeAPI::QueryServiceStatusEx($ServiceHandle, 0, $StatusBuffer, 36, [ref]$BytesNeeded)) {
                    $TargetPid = [System.Runtime.InteropServices.Marshal]::ReadInt32($StatusBuffer, 28)
                }
                [System.Runtime.InteropServices.Marshal]::FreeHGlobal($StatusBuffer)
                return $TargetPid
            }
            finally { $global:TI_NativeAPI::CloseServiceHandle($ServiceHandle) | Out-Null }
        }
        finally { $global:TI_NativeAPI::CloseServiceHandle($ServiceManagerHandle) | Out-Null }
    }

    function New-SecuredPipeServer {
        param([string]$Name, [System.IO.Pipes.PipeDirection]$Direction)
        $PipeSecurity = New-Object System.IO.Pipes.PipeSecurity
        $AccessAllow = [System.Security.AccessControl.AccessControlType]::Allow
        $AccessFull = [System.IO.Pipes.PipeAccessRights]::FullControl
        $PipeSecurity.AddAccessRule((New-Object System.IO.Pipes.PipeAccessRule((New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')), $AccessFull, $AccessAllow)))
        $PipeSecurity.AddAccessRule((New-Object System.IO.Pipes.PipeAccessRule((New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')), $AccessFull, $AccessAllow)))
        $PipeSecurity.AddAccessRule((New-Object System.IO.Pipes.PipeAccessRule((New-Object System.Security.Principal.SecurityIdentifier('S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')), $AccessFull, $AccessAllow)))
        $PipeOptions = [System.IO.Pipes.PipeOptions]::Asynchronous
        $aclType = [type]::GetType('System.IO.Pipes.NamedPipeServerStreamAcl, System.IO.Pipes.AccessControl', $false)
        if ($aclType) {
            return [System.IO.Pipes.NamedPipeServerStreamAcl]::Create(
                $Name, $Direction, 1,
                [System.IO.Pipes.PipeTransmissionMode]::Byte,
                $PipeOptions, 65536, 65536, $PipeSecurity,
                [System.IO.HandleInheritability]::None,
                [System.IO.Pipes.PipeAccessRights]0
            )
        }
        return New-Object System.IO.Pipes.NamedPipeServerStream($Name, $Direction, 1, [System.IO.Pipes.PipeTransmissionMode]::Byte, $PipeOptions, 65536, 65536, $PipeSecurity)
    }
    
    function Enable-TokenPrivileges {
        param([IntPtr]$TokenHandle, [string[]]$Privileges)
        $TokenPrivilegeSize = 4 + ($Privileges.Count * 12)
        $TokenPrivilegesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenPrivilegeSize)
        try {
            $ZeroBuffer = New-Object byte[] $TokenPrivilegeSize
            [System.Runtime.InteropServices.Marshal]::Copy($ZeroBuffer, 0, $TokenPrivilegesPtr, $TokenPrivilegeSize)
            $ValidPrivilegeCount = 0
            
            foreach ($Privilege in $Privileges) {
                $LocallyUniqueIdentifier = [Int64]0
                $PrivilegeStringPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($Privilege)
                try {
                    if ($global:TI_NativeAPI::LookupPrivilegeValueW([IntPtr]::Zero, $PrivilegeStringPtr, [ref]$LocallyUniqueIdentifier)) {
                        $Offset = 4 + ($ValidPrivilegeCount * 12)
                        [System.Runtime.InteropServices.Marshal]::WriteInt64([IntPtr]($TokenPrivilegesPtr.ToInt64() + $Offset), $LocallyUniqueIdentifier)
                        [System.Runtime.InteropServices.Marshal]::WriteInt32([IntPtr]($TokenPrivilegesPtr.ToInt64() + $Offset + 8), 2)
                        $ValidPrivilegeCount++
                    }
                }
                finally {
                    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($PrivilegeStringPtr)
                }
            }
            [System.Runtime.InteropServices.Marshal]::WriteInt32($TokenPrivilegesPtr, 0, $ValidPrivilegeCount)
            $AdjustResult = $global:TI_NativeAPI::AdjustTokenPrivileges($TokenHandle, $false, $TokenPrivilegesPtr, 0, [IntPtr]::Zero, [IntPtr]::Zero)
            $AdjustLastError = [int]$global:TI_NativeAPI::GetLastError()
            if (-not $AdjustResult) {
                throw (Format-Win32Error -ApiName 'AdjustTokenPrivileges' -ErrorCode $AdjustLastError)
            }
            if ($AdjustLastError -eq 1300) {
                Write-Verbose '[Enable-TokenPrivileges] Not all requested privileges were assigned (ERROR_NOT_ALL_ASSIGNED).'
            }
        }
        finally {
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenPrivilegesPtr)
        }
    }

    if (-not $Command -or $Command.Count -eq 0) { return Write-Error 'Command missing.' }

    $ScriptFilePath = $null
    $JoinedCommand = if ($PowerShell) { 
        $joined = $Command -join ' '
        if ($Command.Count -eq 1 -and $joined -match '(?i)\.ps1$' -and $joined -notmatch '^\s*&') {
            $ScriptFilePath = $joined
        }
        $joined
    }
    else { Join-CmdLiteralArguments $Command }

    if (-not $PSCmdlet.ShouldProcess('TrustedInstaller Identity', "Execute: $JoinedCommand")) { return }

    if (-not (Initialize-NativeBindings)) { return Write-Error 'Failed to initialize native dependencies.' }

    try {
        $CurrentProcessHandle = $global:TI_NativeAPI::GetCurrentProcess()
        $ProcessTokenHandle = [IntPtr]::Zero
        $OpenCurrentTokenResult = $global:TI_NativeAPI::OpenProcessToken($CurrentProcessHandle, 0x0028, [ref]$ProcessTokenHandle)
        $OpenCurrentTokenLastError = [int]$global:TI_NativeAPI::GetLastError()
        if ($OpenCurrentTokenResult) {
            try { Enable-TokenPrivileges -TokenHandle $ProcessTokenHandle -Privileges @('SeDebugPrivilege') }
            finally { Close-SafeHandle ([ref]$ProcessTokenHandle) }
        }
        else {
            Write-Verbose (Format-Win32Error -ApiName 'OpenProcessToken' -ErrorCode $OpenCurrentTokenLastError)
        }
    }
    catch {
        Write-Verbose "An exception occurred during initial token privilege assignment: $_"
    }

    $RestoreDisabledTrustedInstaller = $false
    try {
        $TrustedInstallerPid = Get-ServiceProcessId
        if ($TrustedInstallerPid -eq 0) {
            $TiService = Get-Service -Name 'TrustedInstaller' -ErrorAction SilentlyContinue
            if ($TiService) {
                if ($TiService.StartType -eq 'Disabled') {
                    Set-Service -Name 'TrustedInstaller' -StartupType Manual -ErrorAction SilentlyContinue
                    $RestoreDisabledTrustedInstaller = $true
                }
                $MaxAttempts = 3
                for ($Attempt = 1; $Attempt -le $MaxAttempts; $Attempt++) {
                    $TiService.Refresh()
                    if ($TiService.Status -ne 'Running') {
                        try { $TiService.Start() } catch { }
                        try { $TiService.WaitForStatus('Running', '00:00:10') } catch { }
                    }
                    $TrustedInstallerPid = Get-ServiceProcessId
                    if ($TrustedInstallerPid -ne 0) { break }
                    if ($Attempt -lt $MaxAttempts) { [System.Threading.Thread]::Sleep(500) }
                }
            }
        }
        if ($TrustedInstallerPid -eq 0) { throw 'TrustedInstaller service not found.' }

        $CurrentDirectory = (Get-Location -PSProvider FileSystem).ProviderPath

        if ($PowerShell) {
            $DuplicatedToken = [IntPtr]::Zero
            $TiToken = [IntPtr]::Zero
            $ParentProcessHandle = [IntPtr]::Zero
            $RevertRequired = $false
            $SystemProcessHandle = [IntPtr]::Zero
            $SystemToken = [IntPtr]::Zero
            $SystemDupToken = [IntPtr]::Zero

            try {
                $WinlogonPid = ([System.Diagnostics.Process]::GetProcessesByName('winlogon') | Select-Object -First 1).Id
                if ($WinlogonPid) {
                    $SystemProcessHandle = $global:TI_NativeAPI::OpenProcess(0x0400, $false, $WinlogonPid)
                    $OpenSystemProcessLastError = [int]$global:TI_NativeAPI::GetLastError()
                    if ($SystemProcessHandle -eq [IntPtr]::Zero) { throw (Format-Win32Error -ApiName 'OpenProcess(winlogon)' -ErrorCode $OpenSystemProcessLastError) }
                    $OpenSystemTokenResult = $global:TI_NativeAPI::OpenProcessToken($SystemProcessHandle, 0x000A, [ref]$SystemToken)
                    $OpenSystemTokenLastError = [int]$global:TI_NativeAPI::GetLastError()
                    if (-not $OpenSystemTokenResult) { throw (Format-Win32Error -ApiName 'OpenProcessToken(winlogon)' -ErrorCode $OpenSystemTokenLastError) }
                    $DuplicateSystemTokenResult = $global:TI_NativeAPI::DuplicateTokenEx($SystemToken, 0x000F01FF, [IntPtr]::Zero, 2, 2, [ref]$SystemDupToken)
                    $DuplicateSystemTokenLastError = [int]$global:TI_NativeAPI::GetLastError()
                    if (-not $DuplicateSystemTokenResult) { throw (Format-Win32Error -ApiName 'DuplicateTokenEx(SYSTEM)' -ErrorCode $DuplicateSystemTokenLastError) }
                    $CurrentThread = $global:TI_NativeAPI::GetCurrentThread()
                    $SetSystemThreadTokenResult = $global:TI_NativeAPI::SetThreadToken([ref]$CurrentThread, $SystemDupToken)
                    $SetSystemThreadTokenLastError = [int]$global:TI_NativeAPI::GetLastError()
                    if (-not $SetSystemThreadTokenResult) { throw (Format-Win32Error -ApiName 'SetThreadToken(SYSTEM)' -ErrorCode $SetSystemThreadTokenLastError) }
                    $RevertRequired = $true
                }

                $ParentProcessHandle = $global:TI_NativeAPI::OpenProcess(0x0400, $false, $TrustedInstallerPid)
                $OpenTiProcessLastError = [int]$global:TI_NativeAPI::GetLastError()
                if ($ParentProcessHandle -eq [IntPtr]::Zero) { throw (Format-Win32Error -ApiName 'OpenProcess(TI)' -ErrorCode $OpenTiProcessLastError) }
                $OpenTiTokenResult = $global:TI_NativeAPI::OpenProcessToken($ParentProcessHandle, 0x000A, [ref]$TiToken)
                $OpenTiTokenLastError = [int]$global:TI_NativeAPI::GetLastError()
                if (-not $OpenTiTokenResult) { throw (Format-Win32Error -ApiName 'OpenProcessToken(TI)' -ErrorCode $OpenTiTokenLastError) }
                $DuplicateTiTokenResult = $global:TI_NativeAPI::DuplicateTokenEx($TiToken, 0x000F01FF, [IntPtr]::Zero, 2, 2, [ref]$DuplicatedToken)
                $DuplicateTiTokenLastError = [int]$global:TI_NativeAPI::GetLastError()
                if (-not $DuplicateTiTokenResult) { throw (Format-Win32Error -ApiName 'DuplicateTokenEx(TI)' -ErrorCode $DuplicateTiTokenLastError) }
    
                $CurrentThread = $global:TI_NativeAPI::GetCurrentThread()
                $SetTiThreadTokenResult = $global:TI_NativeAPI::SetThreadToken([ref]$CurrentThread, $DuplicatedToken)
                $SetTiThreadTokenLastError = [int]$global:TI_NativeAPI::GetLastError()
                if (-not $SetTiThreadTokenResult) { throw (Format-Win32Error -ApiName 'SetThreadToken(TI)' -ErrorCode $SetTiThreadTokenLastError) }
                $RevertRequired = $true


                $global:LASTEXITCODE = 0
                if ($ScriptFilePath) {
                    try {
                        $ResolvedScriptPath = (Resolve-Path -LiteralPath $ScriptFilePath -ErrorAction Stop).ProviderPath
                    }
                    catch {
                        throw "Script file not found: '$ScriptFilePath'. If path contains a backtick, use single quotes or double the backtick."
                    }
                    & $ResolvedScriptPath
                }
                else {
                    $ExecutionBlock = [scriptblock]::Create($JoinedCommand)
                    & $ExecutionBlock
                }
                $PsSuccess = $?

                $global:TIExitCode = if ($null -ne $LASTEXITCODE -and $LASTEXITCODE -ne 0) { $LASTEXITCODE } elseif (-not $PsSuccess) { 1 } else { 0 }
                return
            }
            catch {
                if ($RevertRequired) {
                    Write-Error $_
                }
                else {
                    Write-Error "Impersonation failed: $_"
                }
                $global:TIExitCode = 1
                return
            }
            finally {
                if ($RevertRequired) { $global:TI_NativeAPI::RevertToSelf() | Out-Null }
                Close-SafeHandle ([ref]$DuplicatedToken)
                Close-SafeHandle ([ref]$TiToken)
                Close-SafeHandle ([ref]$ParentProcessHandle)
                Close-SafeHandle ([ref]$SystemDupToken)
                Close-SafeHandle ([ref]$SystemToken)
                Close-SafeHandle ([ref]$SystemProcessHandle)
            }
        }
        else {
            $CurrentTick = [BitConverter]::ToUInt32([BitConverter]::GetBytes([Environment]::TickCount), 0)
            $OutputPipeName = "mojo.$PID.$CurrentTick.$([guid]::NewGuid().ToString('N').Substring(0,16))"
            $CmdExe = Join-Path ([Environment]::SystemDirectory) 'cmd.exe'
            $LaunchCommand = "`"$CmdExe`" /d /s /v:off /c `"chcp 65001 >NUL & ( $JoinedCommand ) > \\.\pipe\$OutputPipeName 2>&1 < NUL`""

            $OutputPipeServer = New-SecuredPipeServer -Name $OutputPipeName -Direction 'In'

            $ParentProcessHandle = $global:TI_NativeAPI::OpenProcess(0x0080, $false, $TrustedInstallerPid)
            $OpenProcessLastError = [int]$global:TI_NativeAPI::GetLastError()
            if ($ParentProcessHandle -eq [IntPtr]::Zero) {
                $OutputPipeServer.Dispose()
                $global:TIExitCode = 1
                return Write-Error (Format-Win32Error -ApiName 'OpenProcess' -ErrorCode $OpenProcessLastError)
            }

            try {
                if ([Environment]::Is64BitProcess) { $StartupInfoSize = 112; $StartupInfoAttributeOffset = 104; $ProcessInfoSize = 24 } else { $StartupInfoSize = 72; $StartupInfoAttributeOffset = 68; $ProcessInfoSize = 16 }
                $StartupInfoPtr = [IntPtr]::Zero
                $ProcessInfoPtr = [IntPtr]::Zero
                $AttributeListPtr = [IntPtr]::Zero
                $ApplicationPtr = [IntPtr]::Zero
                $CommandPtr = [IntPtr]::Zero
                $CurrentDirPtr = [IntPtr]::Zero
                $ParentHandlePtr = [IntPtr]::Zero
                $MitigationPolicyPtr = [IntPtr]::Zero
                $ProcessHandle = [IntPtr]::Zero
                $ThreadHandle = [IntPtr]::Zero
                $CompletionPortHandle = [IntPtr]::Zero
                $JobObjectHandle = [IntPtr]::Zero
                $JobLimitInfoPtr = [IntPtr]::Zero
                $EnvironmentPtr = [IntPtr]::Zero
                $AttributeListInitialized = $false

                $StartupInfoPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($StartupInfoSize)
                $ProcessInfoPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($ProcessInfoSize)

                $ZeroStartupInfo = New-Object byte[] $StartupInfoSize
                $ZeroProcessInfo = New-Object byte[] $ProcessInfoSize
                [System.Runtime.InteropServices.Marshal]::Copy($ZeroStartupInfo, 0, $StartupInfoPtr, $StartupInfoSize)
                [System.Runtime.InteropServices.Marshal]::Copy($ZeroProcessInfo, 0, $ProcessInfoPtr, $ProcessInfoSize)
                [System.Runtime.InteropServices.Marshal]::WriteInt32($StartupInfoPtr, 0, $StartupInfoSize)

                $AttributeSize = [IntPtr]::Zero
                $null = $global:TI_NativeAPI::InitializeProcThreadAttributeList([IntPtr]::Zero, 2, 0, [ref]$AttributeSize)
                $AttributeListPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($AttributeSize)

                $InitializeAttributeListResult = $global:TI_NativeAPI::InitializeProcThreadAttributeList($AttributeListPtr, 2, 0, [ref]$AttributeSize)
                $InitializeAttributeListLastError = [int]$global:TI_NativeAPI::GetLastError()
                if (-not $InitializeAttributeListResult) {
                    throw (Format-Win32Error -ApiName 'InitializeProcThreadAttributeList' -ErrorCode $InitializeAttributeListLastError)
                }
                $AttributeListInitialized = $true

                $ParentHandlePtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([IntPtr]::Size)
                [System.Runtime.InteropServices.Marshal]::WriteIntPtr($ParentHandlePtr, $ParentProcessHandle)
                $UpdateParentAttributeResult = $global:TI_NativeAPI::UpdateProcThreadAttribute($AttributeListPtr, 0, [IntPtr]0x00020000, $ParentHandlePtr, [IntPtr][IntPtr]::Size, [IntPtr]::Zero, [IntPtr]::Zero)
                $UpdateParentAttributeLastError = [int]$global:TI_NativeAPI::GetLastError()
                if (-not $UpdateParentAttributeResult) {
                    throw (Format-Win32Error -ApiName 'UpdateProcThreadAttribute(PARENT_PROCESS)' -ErrorCode $UpdateParentAttributeLastError)
                }

                $MitigationPolicyPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(8)
                [System.Runtime.InteropServices.Marshal]::WriteInt64($MitigationPolicyPtr, [Int64]0x100000000000)
                $UpdateMitigationAttributeResult = $global:TI_NativeAPI::UpdateProcThreadAttribute($AttributeListPtr, 0, [IntPtr]0x00020007, $MitigationPolicyPtr, [IntPtr]8, [IntPtr]::Zero, [IntPtr]::Zero)
                $UpdateMitigationAttributeLastError = [int]$global:TI_NativeAPI::GetLastError()
                if (-not $UpdateMitigationAttributeResult) {
                    throw (Format-Win32Error -ApiName 'UpdateProcThreadAttribute(MITIGATION_POLICY)' -ErrorCode $UpdateMitigationAttributeLastError)
                }

                [System.Runtime.InteropServices.Marshal]::WriteIntPtr([IntPtr]($StartupInfoPtr.ToInt64() + $StartupInfoAttributeOffset), $AttributeListPtr)

                $ApplicationPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($CmdExe)
                $CommandPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($LaunchCommand)
                $CurrentDirPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($CurrentDirectory)

                $EnvironmentPtr = $global:TI_NativeAPI::GetEnvironmentStringsW()

                $CreateProcessResult = $global:TI_NativeAPI::CreateProcessW($ApplicationPtr, $CommandPtr, [IntPtr]::Zero, [IntPtr]::Zero, $false, 0x08080404, $EnvironmentPtr, $CurrentDirPtr, $StartupInfoPtr, $ProcessInfoPtr)
                $CreateProcessLastError = [int]$global:TI_NativeAPI::GetLastError()

                if (-not $CreateProcessResult) { throw (Format-Win32Error -ApiName 'CreateProcessW' -ErrorCode $CreateProcessLastError) }

                $ProcessHandle = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($ProcessInfoPtr, 0)
                $ThreadHandle = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($ProcessInfoPtr, [IntPtr]::Size)
                if ($ProcessHandle -eq [IntPtr]::Zero -or $ThreadHandle -eq [IntPtr]::Zero) { throw 'CreateProcess returned invalid handles.' }

                $JobObjectHandle = $global:TI_NativeAPI::CreateJobObjectW([IntPtr]::Zero, [IntPtr]::Zero)
                if ($JobObjectHandle -ne [IntPtr]::Zero) {
                    $JobExtSize = if ([Environment]::Is64BitProcess) { 144 } else { 112 }
                    $JobLimitInfoPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($JobExtSize)
                    $ZeroJob = New-Object byte[] $JobExtSize
                    [System.Runtime.InteropServices.Marshal]::Copy($ZeroJob, 0, $JobLimitInfoPtr, $JobExtSize)
                    [System.Runtime.InteropServices.Marshal]::WriteInt32([IntPtr]($JobLimitInfoPtr.ToInt64() + 16), 0x2000)
                    $global:TI_NativeAPI::SetInformationJobObject($JobObjectHandle, 9, $JobLimitInfoPtr, $JobExtSize) | Out-Null
                    $global:TI_NativeAPI::AssignProcessToJobObject($JobObjectHandle, $ProcessHandle) | Out-Null

                    $CompletionPortHandle = $global:TI_NativeAPI::CreateIoCompletionPort([IntPtr](-1), [IntPtr]::Zero, [IntPtr]::Zero, 1)
                    if ($CompletionPortHandle -ne [IntPtr]::Zero) {
                        $JoacpSize = 2 * [IntPtr]::Size
                        $JoacpPtr = [IntPtr]::Zero
                        try {
                            $JoacpPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($JoacpSize)
                            [System.Runtime.InteropServices.Marshal]::WriteIntPtr($JoacpPtr, 0, [IntPtr]1)
                            [System.Runtime.InteropServices.Marshal]::WriteIntPtr([IntPtr]($JoacpPtr.ToInt64() + [IntPtr]::Size), $CompletionPortHandle)
                            $global:TI_NativeAPI::SetInformationJobObject($JobObjectHandle, 7, $JoacpPtr, [UInt32]$JoacpSize) | Out-Null
                        }
                        finally {
                            if ($JoacpPtr -ne [IntPtr]::Zero) {
                                [System.Runtime.InteropServices.Marshal]::FreeHGlobal($JoacpPtr)
                                $JoacpPtr = [IntPtr]::Zero
                            }
                        }
                    }
                }

                $ChildTok = [IntPtr]::Zero
                try {
                    if ($global:TI_NativeAPI::OpenProcessToken($ProcessHandle, 0x0028, [ref]$ChildTok)) {
                        Enable-TokenPrivileges -TokenHandle $ChildTok -Privileges @(
                            'SeCreateTokenPrivilege', 'SeAssignPrimaryTokenPrivilege', 'SeLockMemoryPrivilege',
                            'SeIncreaseQuotaPrivilege', 'SeUnsolicitedInputPrivilege', 'SeMachineAccountPrivilege',
                            'SeTcbPrivilege', 'SeSecurityPrivilege', 'SeTakeOwnershipPrivilege',
                            'SeLoadDriverPrivilege', 'SeSystemProfilePrivilege', 'SeSystemtimePrivilege',
                            'SeProfileSingleProcessPrivilege', 'SeIncreaseBasePriorityPrivilege', 'SeCreatePagefilePrivilege',
                            'SeCreatePermanentPrivilege', 'SeBackupPrivilege', 'SeRestorePrivilege',
                            'SeShutdownPrivilege', 'SeDebugPrivilege', 'SeAuditPrivilege',
                            'SeSystemEnvironmentPrivilege', 'SeChangeNotifyPrivilege', 'SeRemoteShutdownPrivilege',
                            'SeUndockPrivilege', 'SeSyncAgentPrivilege', 'SeEnableDelegationPrivilege',
                            'SeManageVolumePrivilege', 'SeImpersonatePrivilege', 'SeCreateGlobalPrivilege',
                            'SeTrustedCredmanAccessPrivilege', 'SeRelabelPrivilege', 'SeIncreaseWorkingSetPrivilege',
                            'SeTimeZonePrivilege', 'SeCreateSymbolicLinkPrivilege', 'SeDelegateSessionUserImpersonatePrivilege'
                        )
                    }
                }
                finally { Close-SafeHandle ([ref]$ChildTok) }

                $OutputAsyncWait = $OutputPipeServer.BeginWaitForConnection($null, $null)
                $PipeConnected = $false

                $ResumeResult = $global:TI_NativeAPI::ResumeThread($ThreadHandle)
                $ResumeLastError = [int]$global:TI_NativeAPI::GetLastError()
                if ($ResumeResult -eq 0xFFFFFFFF) {
                    throw (Format-Win32Error -ApiName 'ResumeThread' -ErrorCode $ResumeLastError)
                }
                Close-SafeHandle ([ref]$ThreadHandle)

                $Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
                $PipeSafeHandle = $OutputPipeServer.SafePipeHandle.DangerousGetHandle()
                $Utf8Decoder = [System.Text.Encoding]::UTF8.GetDecoder()

                $ReadBuffer = New-Object byte[] 65536
                $CharBuffer = New-Object char[] 65536
                $StringBuilder = [System.Text.StringBuilder]::new(65536)

                while ($TimeoutSec -eq 0 -or $Stopwatch.Elapsed.TotalSeconds -lt $TimeoutSec) {
                    if ($OutputAsyncWait.IsCompleted) {
                        try { $OutputPipeServer.EndWaitForConnection($OutputAsyncWait) } catch { }
                        $PipeConnected = $true
                        break
                    }
                    if ($global:TI_NativeAPI::WaitForSingleObject($ProcessHandle, 15) -eq 0) {
                        if (-not $OutputAsyncWait.IsCompleted) { [void]$OutputAsyncWait.AsyncWaitHandle.WaitOne(500) }
                        if ($OutputAsyncWait.IsCompleted) {
                            try { $OutputPipeServer.EndWaitForConnection($OutputAsyncWait) } catch { }
                            $PipeConnected = $true
                        }
                        break
                    }
                }

                if (-not $PipeConnected -and $TimeoutSec -gt 0 -and $Stopwatch.Elapsed.TotalSeconds -ge $TimeoutSec) {
                    Write-Warning "[!] Process exceeded ${TimeoutSec}s timeout before output pipe connection. Forcefully terminated."
                    $null = $global:TI_NativeAPI::TerminateProcess($ProcessHandle, 1)
                }

                if ($PipeConnected) {
                    $ProcessExited = $false
                    while ($true) {
                        $TotalBytesAvailable = [UInt32]0
                        $HasData = $global:TI_NativeAPI::PeekNamedPipe($PipeSafeHandle, [IntPtr]::Zero, 0, [IntPtr]::Zero, [ref]$TotalBytesAvailable, [IntPtr]::Zero)

                        if (-not $HasData -or $TotalBytesAvailable -eq 0) {
                            if ($ProcessExited) { break }

                            if ($global:TI_NativeAPI::WaitForSingleObject($ProcessHandle, 0) -eq 0) {
                                $ProcessExited = $true
                            }

                            if (-not $ProcessExited) {
                                if ($CompletionPortHandle -ne [IntPtr]::Zero) {
                                    $BytesTransferred = [UInt32]0
                                    $CompletionKey = [IntPtr]::Zero
                                    $OverlappedPtr = [IntPtr]::Zero
                                    if ($global:TI_NativeAPI::GetQueuedCompletionStatus($CompletionPortHandle, [ref]$BytesTransferred, [ref]$CompletionKey, [ref]$OverlappedPtr, 15)) {
                                        if ($BytesTransferred -eq 4) { $ProcessExited = $true }
                                    }
                                }
                                else {
                                    if ($global:TI_NativeAPI::WaitForSingleObject($ProcessHandle, 15) -eq 0) { $ProcessExited = $true }
                                }
                            }

                            if ($TimeoutSec -gt 0 -and $Stopwatch.Elapsed.TotalSeconds -ge $TimeoutSec) {
                                Write-Warning "[!] Process exceeded ${TimeoutSec}s timeout. Forcefully terminated."
                                $null = $global:TI_NativeAPI::TerminateProcess($ProcessHandle, 1)
                                break
                            }
                            continue
                        }

                        $BytesToRead = [Math]::Min([int]$TotalBytesAvailable, 65536)
                        try {
                            $BytesRead = $OutputPipeServer.Read($ReadBuffer, 0, $BytesToRead)
                        }
                        catch [System.IO.IOException] {
                            break
                        }
                        $CharsDecodedCount = $Utf8Decoder.GetChars($ReadBuffer, 0, $BytesRead, $CharBuffer, 0)
                        $null = $StringBuilder.Append($CharBuffer, 0, $CharsDecodedCount)

                        $ContainsNewline = $false
                        for ($i = 0; $i -lt $CharsDecodedCount; $i++) {
                            if ($CharBuffer[$i] -eq [char]10) { $ContainsNewline = $true; break }
                        }

                        if ($ContainsNewline) {
                            $CurrentString = $StringBuilder.ToString()
                            $LastNewlineIndex = $CurrentString.LastIndexOf([char]10)

                            if ($LastNewlineIndex -ge 0) {
                                $LinesToProcess = $CurrentString.Substring(0, $LastNewlineIndex)
                                $Lines = $LinesToProcess.Split([char]10)

                                foreach ($Line in $Lines) {
                                    $CleanLine = $Line.TrimEnd([char]13)
                                    Write-Output $CleanLine
                                }

                                $null = $StringBuilder.Remove(0, $LastNewlineIndex + 1)
                            }
                        }
                    }

                    if ($StringBuilder.Length -gt 0) {
                        $FinalString = $StringBuilder.ToString()
                        Write-Output $FinalString
                    }
                }
                else {
                    Write-Verbose "Output pipe server was not connected. Output stream could not be captured."
                }
            }
            catch {
                $global:TIExitCode = 1
                Write-Error $_.Exception.Message
                if ($ProcessHandle -ne [IntPtr]::Zero) {
                    $null = $global:TI_NativeAPI::TerminateProcess($ProcessHandle, 1)
                }
            }
            finally {
                if ($OutputPipeServer) { try { $OutputPipeServer.Dispose() } catch { } }

                $ExitCode = [int]0
                if ($ProcessHandle -ne [IntPtr]::Zero -and $global:TI_NativeAPI::GetExitCodeProcess($ProcessHandle, [ref]$ExitCode)) {
                    if ($ExitCode -eq 259) {
                        $null = $global:TI_NativeAPI::WaitForSingleObject($ProcessHandle, 5000)
                        $null = $global:TI_NativeAPI::GetExitCodeProcess($ProcessHandle, [ref]$ExitCode)
                        if ($ExitCode -eq 259) { $ExitCode = -1 }
                    }
                    $global:TIExitCode = $ExitCode
                    $global:LASTEXITCODE = $ExitCode
                }

                Close-SafeHandle ([ref]$ThreadHandle)
                Close-SafeHandle ([ref]$ProcessHandle)
                Close-SafeHandle ([ref]$ParentProcessHandle)
                Close-SafeHandle ([ref]$JobObjectHandle)
                Close-SafeHandle ([ref]$CompletionPortHandle)

                Clear-SafeHGlobal ([ref]$ApplicationPtr)
                Clear-SafeHGlobal ([ref]$CommandPtr)
                Clear-SafeHGlobal ([ref]$CurrentDirPtr)
                Clear-SafeHGlobal ([ref]$ParentHandlePtr)
                Clear-SafeHGlobal ([ref]$MitigationPolicyPtr)
                Clear-SafeHGlobal ([ref]$JobLimitInfoPtr)

                if ($EnvironmentPtr -ne [IntPtr]::Zero) {
                    $global:TI_NativeAPI::FreeEnvironmentStringsW($EnvironmentPtr) | Out-Null
                    $EnvironmentPtr = [IntPtr]::Zero
                }

                if ($AttributeListInitialized -and $AttributeListPtr -ne [IntPtr]::Zero) {
                    $global:TI_NativeAPI::DeleteProcThreadAttributeList($AttributeListPtr)
                    $AttributeListInitialized = $false
                }

                Clear-SafeHGlobal ([ref]$AttributeListPtr)
                Clear-SafeHGlobal ([ref]$StartupInfoPtr)
                Clear-SafeHGlobal ([ref]$ProcessInfoPtr)

                if ($OutputAsyncWait) { try { $OutputAsyncWait.AsyncWaitHandle.Dispose() } catch { } }
            }
        }
    }
    finally {
        if ($RestoreDisabledTrustedInstaller) {
            try { Set-Service -Name 'TrustedInstaller' -StartupType Disabled -ErrorAction SilentlyContinue } catch { }
        }
    }
}

New-Alias -Name ti -Value TrustedInstaller -Scope Global -Force -ErrorAction SilentlyContinue

if ($args.Count -gt 0) { TrustedInstaller @args }

# SIG # Begin signature block
# MIIFhgYJKoZIhvcNAQcCoIIFdzCCBXMCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAmXZ+SvvTEXZ87
# 72SX6rKYx3NF9kQIpzmtTs0XhDqBY6CCAwAwggL8MIIB5KADAgECAhA4javxMBrB
# gUIz2JIluuyNMA0GCSqGSIb3DQEBCwUAMBYxFDASBgNVBAMMC1Bvd2Vyc2hlbGxv
# MB4XDTI2MDUwNjEzNDQxOVoXDTI3MDUwNjE0MDQxOVowFjEUMBIGA1UEAwwLUG93
# ZXJzaGVsbG8wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCjPdqC0lkV
# oH9HnxgI3MOh5uewEnWyU3umpEfhdv3u9Eo/7rhk3XlmGbQy9zh3vKzh/FL5P+8a
# OVC9Hz3PukiyEuVGiOXkfeLIUPEQUttISylYTsZvpbgLRYoq9QHbxe2/L5EDaqTL
# izibxjRU2+JFRKGCHvXxwF45JQCjn+mwpIX3l0gtenEklOMQgMlyyL9EF3K69KCE
# 55f2xrBPWZOE94rHMr655geKvxCYRv19gUssk17mHkWYVWNkr7wLbjmjZgC88XX7
# ftEqWquYKJ3DxLTItdrg2ePzzTrnOUeswKgplUBSnD+hNT9jSA+6jxmLIra2s/gH
# OA8YBaY9SzvVAgMBAAGjRjBEMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggr
# BgEFBQcDAzAdBgNVHQ4EFgQUIUguv0bb4pmgM8OcB9QLrAl1jQcwDQYJKoZIhvcN
# AQELBQADggEBAFKrSLyqnAfOfzkijUsUg06om4YWLg3kVL+VJc0txcKocPvz6oQb
# pGqUc1xuyAQCWDbo1Ufj9F+ubYsRakDu+NdaZI008ArGGbI4VFhpfwu9r5pUaiLj
# SU4l5f1IIhKjPVMS6i83oGGexlCh6mbVYMd4Saxxy2rpzRbfxCC6mSpf7ngPIJME
# 2ToR+C8MD4XYe8M4H0rKdM2lSqH48lsWQFFi3pP7H1vayopTEt9t6eNa8/k9b2Kl
# rFaYlgfiXM0aQi9eBDgrWpmmJmaQzjrxyEq7GWxmjgY6Z4VQsPmAMTFw3I98pCOe
# V8WAzgUIiBGkqq4LcxeADC7K0z7FxofWfMExggHcMIIB2AIBATAqMBYxFDASBgNV
# BAMMC1Bvd2Vyc2hlbGxvAhA4javxMBrBgUIz2JIluuyNMA0GCWCGSAFlAwQCAQUA
# oIGEMBgGCisGAQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisG
# AQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcN
# AQkEMSIEINBceWcU0siOPeFgTgi/D3+56X/+2PyJ32TsU6hIWNdvMA0GCSqGSIb3
# DQEBAQUABIIBAGOZCsOhD5Ot6WdvzsIZGokNpq0dBXAGpYjRvXHASGRvDYe1Tm6M
# NAXfTcNFOUxRzaMrvQxUMdGje56SM5MapNXIV3sDvSyTm1bSDNxQtAwjK3OC7+yl
# XPlRHjASwm+UtteeVKuocwlun3BAY45rEnVWyZYqlmE261v8X41QFG5PyZ/Ksgtt
# pVi4NRS41uIKsMS3xZxEkgsZV4zIDQrhp/RZyMkHDREYJdmtJZUymOgIhSOor1Da
# wsQ9Al6oefXyQUn0NR52exgvx8XmxVg6WsuP9lNnFvYkogSfveVJg5ZkxvcTOrRT
# 4zw+lnN+/RuDyuT1tMgVwCa2pCYmfm+en+w=
# SIG # End signature block
