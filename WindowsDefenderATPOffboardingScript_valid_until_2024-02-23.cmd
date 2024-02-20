@echo off

echo.
echo Starting Microsoft Defender for Endpoint offboarding process...
echo.

set errorCode=0
set lastError=0
set "troubleshootInfo=For more information, visit: https://go.microsoft.com/fwlink/p/?linkid=822807"
set "errorDescription="

echo Testing administrator privileges

%windir%\System32\net.exe session >NUL 2>&1
if %ERRORLEVEL% NEQ 0 (
	@echo Script is running with insufficient privileges. Please run with administrator privileges> %WINDIR%\temp\senseTmp.txt
	set errorCode=65
 set lastError=%ERRORLEVEL%
	GOTO ERROR
)

echo Script is running with sufficient privileges
echo.
echo Performing offboarding operations
echo.

IF [%PROCESSOR_ARCHITEW6432%] EQU [] (
  set powershellPath=%windir%\System32\WindowsPowerShell\v1.0\powershell.exe
) ELSE (
  set powershellPath=%windir%\SysNative\WindowsPowerShell\v1.0\powershell.exe
)

%windir%\System32\reg.exe query "HKLM\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status" /v OrgId >NUL 2>&1
if %ERRORLEVEL% NEQ 0 (
    GOTO AFTER_ORG_EQUALITY_CHECK
)
%windir%\System32\reg.exe query "HKLM\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status" /v OrgId | %windir%\System32\find.exe /i "99d1c52c-a198-4a16-8826-0a81f6f4ea5a" >NUL 2>&1
if %ERRORLEVEL% NEQ 0 (  
    set "errorDescription=Offboarding script for org 99d1c52c-a198-4a16-8826-0a81f6f4ea5a. Machine is onboarded to a different org."
    set errorCode=70
    set lastError=%ERRORLEVEL%
    GOTO ERROR
)
:AFTER_ORG_EQUALITY_CHECK

%windir%\System32\reg.exe query "HKLM\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection" /v OnboardingInfo /reg:64 > %WINDIR%\temp\senseTmp.txt 2>&1
if %ERRORLEVEL% EQU 0 (  
    %windir%\System32\reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection" /v OnboardingInfo /f > %WINDIR%\temp\senseTmp.txt 2>&1
    if %ERRORLEVEL% NEQ 0 (
        set "errorDescription=Unable to delete previous onboarding information from registry."
        set errorCode=5
        set lastError=%ERRORLEVEL%
        GOTO ERROR
    )
)

%windir%\System32\reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection" /v 696C1FA1-4030-4FA4-8713-FAF9B2EA7C0A /t REG_SZ /f /d "{\"body\":\"{\\\"orgIds\\\":[\\\"99d1c52c-a198-4a16-8826-0a81f6f4ea5a\\\"],\\\"orgId\\\":\\\"99d1c52c-a198-4a16-8826-0a81f6f4ea5a\\\",\\\"expirationTimestamp\\\":133531644529324807,\\\"version\\\":\\\"1.65\\\"}\",\"sig\":\"1fC2cFuTFobqQl8V4yz3NeDZ1thMCQAqMuCaqCrTHd2rqpXF23yUJP0ty9KdhhI6j3MvzEm/o752DYCe3iihshQHiVrG2yi7E6PFRup5snVj2j2CPiegvw27JWZaQTcsX2YF1mN/p7vYkCghdu3XsFjd/bnamVNqFrYsi11n3vAHJfD4vYGeyyxwTB6vXjK7M2bwV/DolebioHDVFx4XUJFNvQgakWfZGqNCPY0wXNnfwdObstnmxihMT/0VejVU3CpZg+f6NVAeZash623SMhDVVUxJHVsgeKaJwV0ENvEQ6rD4FnvPgQtc0veAYlujklE8DM4HE2FSS19PKz2nGg==\",\"sha256sig\":\"1fC2cFuTFobqQl8V4yz3NeDZ1thMCQAqMuCaqCrTHd2rqpXF23yUJP0ty9KdhhI6j3MvzEm/o752DYCe3iihshQHiVrG2yi7E6PFRup5snVj2j2CPiegvw27JWZaQTcsX2YF1mN/p7vYkCghdu3XsFjd/bnamVNqFrYsi11n3vAHJfD4vYGeyyxwTB6vXjK7M2bwV/DolebioHDVFx4XUJFNvQgakWfZGqNCPY0wXNnfwdObstnmxihMT/0VejVU3CpZg+f6NVAeZash623SMhDVVUxJHVsgeKaJwV0ENvEQ6rD4FnvPgQtc0veAYlujklE8DM4HE2FSS19PKz2nGg==\",\"sha256sigPss\":\"bYg2bkFj6dVSHfol2gEqe7/JI//A3daKZjzOcNXn4zZ3dRknYEU6nB9RkrDWmeHH99BUMQRN+QIFHVyAEL769QuO8WMwgQqgZXIaPHhxu7qcgt1bf7d4nJKzDtlIl5KyTfvsxkg1UDV/i0lKNgAhv9iM9bUzMvFMWV30m7kZWVs+1YiyOSQpJJPHgtvZMoVqBs9j0WaOFvXZwEwqyaaFa/sD1OR0fujqNSjTcqiVDhDOsJFuXwbZMS+KAYThB3G8vU3CN+yUadA5Guk3OY+czqa9o7gZ+S+caYFXJ6MyNeXK3Utrp8iXYRrVut9jTAiJPjermUiH1m0SiJMTVpjQJg==\",\"cert\":\"MIIFgzCCA2ugAwIBAgITMwAAAnC9JQaUXdnbOQAAAAACcDANBgkqhkiG9w0BAQsFADB+MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYDVQQDEx9NaWNyb3NvZnQgU2VjdXJlIFNlcnZlciBDQSAyMDExMB4XDTIzMTExNjE5NTQzN1oXDTI0MTExNjE5NTQzN1owHjEcMBoGA1UEAxMTU2V2aWxsZS5XaW5kb3dzLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANQZfNcFafxSdB/egdAdSgOht1aMfHgOvgVP6y60sdFt6XThN2urPV/Je+N3Fdx7tnUU3brt7FeUBJVLSRFjUh/mrno9R45NGO6Se92rdIpgG9U7GGl8vlsRF94qMW3oBzSBDoN7Fa/8MKw4A+grADuTorfGh9bDxcpk6p8sv0DUigIomBrB77WrkqcRDrBhX5HXZCRNFP9c7xgGKOLBTaTDa2UOl3y0P1a19NtcBbgj54MxaHbYHo/O946FuE8smCNSjLf/lbgcccS4D8rQ8o1rfQ/M+LNghADzZFYmdcdRYXwjwKdA9jJXJ2SQiecD0JwR3ts6NYVCf9welyF0MfECAwEAAaOCAVgwggFUMA4GA1UdDwEB/wQEAwIFIDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADAeBgNVHREEFzAVghNTZXZpbGxlLldpbmRvd3MuY29tMB0GA1UdDgQWBBRpiFs3F5ZHklNMEctgTfo+RyXrqjAfBgNVHSMEGDAWgBQ2VollSctbmy88rEIWUE2RuTPXkTBTBgNVHR8ETDBKMEigRqBEhkJodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNTZWNTZXJDQTIwMTFfMjAxMS0xMC0xOC5jcmwwYAYIKwYBBQUHAQEEVDBSMFAGCCsGAQUFBzAChkRodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY1NlY1NlckNBMjAxMV8yMDExLTEwLTE4LmNydDANBgkqhkiG9w0BAQsFAAOCAgEAxsbr9TCEIMqQLIQv2PAo+qe6L2WIQCWZ7hDOqKvC9weJ7DVWlEiTonsg7lrRxcUe3PAoeIVzpWts2ZRw5bsDEdZ1VN7u6IZuEpB9J+RGXGhHSL/Hzb8HWcjATM7QnWCNGXJyOj0nwIh18DHNNlQaCd9Q5RVZBELld8XbVbtRu2olBEn6Ex09iuFGuaXc0cwp7v2RHvypihxi099HaR2bn7Nef4ZHPVmxnlUEK6gdUSY2MSGUxyMEJevDiPY7y4nSZIlnsPicFg96WfWhPmyHIaflKgT2bwEy6pgSXCqgGc3OxEVeQTaYo+CXeAYfthrv6v5dOUS/xPaQ1zxDvEZT5k9HBO+52FkOWqhv6qlZu0yQmo0ea4h9iQ8em9H+/LlCRnGKnJiQPSxwlx8P5slhEMxtGrQzZf2ejeYzv3v5EuKW2RyX4mTToVxkHKqXsYtu+ETDccBho4KEWvZ6771fDp0f97S+64NMQR2/wL+FGKLyXlSpRADe1IRBWVB9TnmVt1siex/BT6vw2BvdfksztGF3JDa7c7PtvurWAEiMDa7AqpDowoWAwYX2WJLcoA5IPzTtDTdm1RLIM0TAumFR/l30QtY6RV0XuqfC0eV6deYsKwadugJqQpzxdxvgJExho7OZyG1OrZjJQPtIxNraK7Sukl2zJIKCoHk17RhChg0=\",\"chain\":[\"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\"]}" > %WINDIR%\temp\senseTmp.txt 2>&1
if %ERRORLEVEL% NEQ 0 (
   set "errorDescription=Unable to write offboarding information to registry."
   set errorCode=10
   set lastError=%ERRORLEVEL%
   GOTO ERROR
)

set /a counter=0

:SENSE_STOPPED_WAIT
%windir%\System32\sc.exe query "SENSE" | %windir%\System32\find.exe /i "STOPPED" >NUL 2>&1
if %ERRORLEVEL% NEQ 0 (
	IF %counter% EQU 10 (
		@echo Microsoft Defender for Endpoint Service failed to stop running!> %WINDIR%\temp\senseTmp.txt
		set errorCode=15
     set lastError=%ERRORLEVEL%
		GOTO ERROR
	)

	set /a counter=%counter%+1
	%windir%\System32\timeout.exe 10 >NUL 2>&1

	GOTO :SENSE_STOPPED_WAIT
)

set "successOutput=Successfully offboarded machine from Microsoft Defender for Endpoint"
%powershellPath% -ExecutionPolicy Bypass -NoProfile -Command "Add-Type 'using System; using System.Diagnostics; using System.Diagnostics.Tracing; namespace Sense { [EventData(Name = \"Offboarding\")]public struct Offboarding{public string Message { get; set; }} public class Trace {public static EventSourceOptions TelemetryCriticalOption = new EventSourceOptions(){Level = EventLevel.Informational, Keywords = (EventKeywords)0x0000200000000000, Tags = (EventTags)0x0200000}; public void WriteOffboardingMessage(string message){es.Write(\"OffboardingScript\", TelemetryCriticalOption, new Offboarding {Message = message});} private static readonly string[] telemetryTraits = { \"ETW_GROUP\", \"{5ECB0BAC-B930-47F5-A8A4-E8253529EDB7}\" }; private EventSource es = new EventSource(\"Microsoft.Windows.Sense.Client.Management\",EventSourceSettings.EtwSelfDescribingEventFormat,telemetryTraits);}}'; $logger = New-Object -TypeName Sense.Trace; $logger.WriteOffboardingMessage('%successOutput%')" >NUL 2>&1
echo %successOutput%
echo.
%windir%\System32\eventcreate.exe /l Application /so WDATPOffboarding /t Information /id 20 /d "%successOutput%" >NUL 2>&1

goto EXIT

:ERROR
Set /P errorMsg=<%WINDIR%\temp\senseTmp.txt
set "errorOutput=[Error Id: %errorCode%, Error Level: %lastError%] %errorDescription% Error message: %errorMsg%"
%powershellPath% -ExecutionPolicy Bypass -NoProfile -Command "Add-Type 'using System; using System.Diagnostics; using System.Diagnostics.Tracing; namespace Sense { [EventData(Name = \"Offboarding\")]public struct Offboarding{public string Message { get; set; }} public class Trace {public static EventSourceOptions TelemetryCriticalOption = new EventSourceOptions(){Level = EventLevel.Error, Keywords = (EventKeywords)0x0000200000000000, Tags = (EventTags)0x0200000}; public void WriteOffboardingMessage(string message){es.Write(\"OffboardingScript\", TelemetryCriticalOption, new Offboarding {Message = message});} private static readonly string[] telemetryTraits = { \"ETW_GROUP\", \"{5ECB0BAC-B930-47F5-A8A4-E8253529EDB7}\" }; private EventSource es = new EventSource(\"Microsoft.Windows.Sense.Client.Management\",EventSourceSettings.EtwSelfDescribingEventFormat,telemetryTraits);}}'; $logger = New-Object -TypeName Sense.Trace; $logger.WriteOffboardingMessage('%errorOutput%')" >NUL 2>&1
echo %errorOutput%
echo %troubleshootInfo%
echo.
%windir%\System32\eventcreate.exe /l Application /so WDATPOffboarding /t Error /id %errorCode% /d "%errorOutput%" >NUL 2>&1
goto EXIT

:EXIT
if exist %WINDIR%\temp\senseTmp.txt del %WINDIR%\temp\senseTmp.txt
pause
EXIT /B %errorCode%

