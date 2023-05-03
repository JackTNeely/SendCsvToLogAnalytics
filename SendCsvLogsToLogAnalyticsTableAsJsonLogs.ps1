# Replace with your Workspace ID. This is under "Azure Portal -> your Azure Monitor workspace -> Agents -> workspace ID."
$CustomerId = <Enter Your Workspace ID>

# Replace with your Primary Key. This is under "Azure Portal -> your Azure Monitor workspace -> Agents -> primary key."
$SharedKey = <Enter your Primary Key>

# Specify the name of the record type that you'll be creating. This is also the 
$LogType = "ApiTest10" 

$SourceDirectory      = "C:\CsvLogs"
$DestinationDirectory = "C:\ApiLogs"

# Create the function to create the authorization signature
Function Build-Signature ($CustomerId, $SharedKey, $Date, $ContentLength, $Method, $ContentType, $Resource)
{
    $XHeaders = "x-ms-date:" + $Date
    $StringToHash = $Method + "`n" + $ContentLength + "`n" + $ContentType + "`n" + $XHeaders + "`n" + $Resource

    $BytesToHash = [Text.Encoding]::UTF8.GetBytes($StringToHash)
    $KeyBytes = [Convert]::FromBase64String($SharedKey)

    $Sha256 = New-Object System.Security.Cryptography.HMACSHA256
    $Sha256.Key = $KeyBytes
    $CalculatedHash = $Sha256.ComputeHash($BytesToHash)
    $EncodedHash = [Convert]::ToBase64String($CalculatedHash)
    $Authorization = 'SharedKey {0}:{1}' -f $CustomerId,$EncodedHash
    return $Authorization
}

# Create the function to create and post the request
Function Submit-LogAnalyticsData($CustomerId, $SharedKey, $Body, $LogType) {
    $Method = "POST"
    $ContentType = "application/json"
    $Resource = "/api/logs"
    $Rfc1123Date = [DateTime]::UtcNow.ToString("r")
    $ContentLength = ([System.Text.Encoding]::UTF8.GetBytes($Body)).Length
    $Signature = Build-Signature `
        -CustomerId $CustomerId `
        -SharedKey $SharedKey `
        -Date $Rfc1123Date `
        -ContentLength $ContentLength `
        -Method $Method `
        -ContentType $ContentType `
        -Resource $Resource
    $Uri = "https://" + $CustomerId + ".ods.opinsights.azure.com" + $Resource + "?api-version=2016-04-01"

    $Headers = @{
        "Authorization" = $Signature;
        "Log-Type" = $LogType;
        "x-ms-date" = $Rfc1123Date;
    }

    $Response = Invoke-WebRequest -Uri $Uri -Method $Method -ContentType $ContentType -Headers $Headers -Body $Body -UseBasicParsing
    return $Response.StatusCode
}

# Create the function to create and post the request
Function Convert-CsvToJson($SourceDirectory, $DestinationDirectory, $CustomerId, $SharedKey, $LogType) {
    if (!(Test-Path -Path $DestinationDirectory)) {
        New-Item -ItemType Directory -Path $DestinationDirectory | Out-Null
    }

    $FileSystemWatcher = New-Object System.IO.FileSystemWatcher
    $FileSystemWatcher.Path = $SourceDirectory
    $FileSystemWatcher.Filter = "*.csv"
    $FileSystemWatcher.EnableRaisingEvents = $true
    $FileSystemWatcher.IncludeSubdirectories = $false
    $FileSystemWatcher.NotifyFilter = [System.IO.NotifyFilters]::FileName -bor [System.IO.NotifyFilters]::LastWrite

    $Action = {
        $CsvFilePath = $Event.SourceEventArgs.FullPath
        Write-Host "Detected change in file: $CsvFilePath" -ForegroundColor Cyan

        try {
            $CsvData = Import-Csv -Path $CsvFilePath
            $JsonData = $CsvData | ConvertTo-Json
            $Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
            $CsvFileName = [System.IO.Path]::GetFileNameWithoutExtension($CsvFilePath)
            $JsonFileName = "{0}-{1}.json" -f $CsvFileName, $Timestamp
            $JsonFilePath = Join-Path -Path $DestinationDirectory -ChildPath $JsonFileName

            if (Test-Path -Path $JsonFilePath) {
                Write-Host "JSON file with the same name already exists: $JsonFilePath" -ForegroundColor Yellow
            } else {
                $JsonData | Set-Content -Path $JsonFilePath
                Write-Host "Created JSON file: $JsonFilePath" -ForegroundColor Cyan

                $StatusCode = Submit-LogAnalyticsData -CustomerId $CustomerId -SharedKey $SharedKey -Body $JsonData -LogType $LogType
                if ($StatusCode -eq 200) {
                    Write-Host "Data successfully submitted to Log Analytics. Status code: $StatusCode" -ForegroundColor Green
                } else {
                    Write-Host "Failed to submit data to Log Analytics. Status code: $StatusCode" -ForegroundColor Red
                }
            }
        } catch {
            Write-Host "An error occurred while processing the file: $CsvFilePath" -ForegroundColor Red
            Write-Host "Error: $_" -ForegroundColor Red
        }
    }

    Register-ObjectEvent -InputObject $FileSystemWatcher -EventName "Changed" -Action $Action
}

Convert-CsvToJson -SourceDirectory $SourceDirectory -DestinationDirectory $DestinationDirectory -CustomerId $CustomerId -SharedKey $SharedKey -LogType $LogType

# Keep the script running indefinitely to continue monitoring for changes.
while ($true) {
    Start-Sleep -Seconds 5
}
