# ScanSensitiveData.ps1

# Define the regular expressions to match credit card numbers and other sensitive information
$patterns = @(
    '\b(?:\d[ -]*?){13,16}\b', # Generic Credit Card Number
    '\b(?:4[0-9]{12}(?:[0-9]{3})?)\b', # Visa
    '\b(?:5[1-5][0-9]{14})\b', # MasterCard
    '\b(?:3[47][0-9]{13})\b', # American Express
    '\b(?:3(?:0[0-5]|[68][0-9])[0-9]{11})\b', # Diners Club
    '\b(?:6(?:011|5[0-9]{2})[0-9]{12})\b', # Discover
    '\b(?:2131|1800|35\d{3})\d{11}\b', # JCB
    '\b\d{3}-\d{2}-\d{4}\b', # SSN (U.S. Social Security Number)
    '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}', # Email Addresses
    '\b[0-9a-zA-Z]{40}\b', # Generic API Keys (40 chars long)
    '\bAKIA[0-9A-Z]{16}\b', # AWS Access Key ID
    '\b(?<!\S)(?:[1-9]\d{0,2}(?:,\d{3})*|0)?(?:\.\d{1,2})?(?!\S)\b' # Currency amount
)

# Get all logical drives
$drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Free -gt 0 }

# Output file for storing results
$outputFile = "C:\ScanResults.txt"

# Create or clear the output file
Clear-Content -Path $outputFile -ErrorAction SilentlyContinue

# Function to scan files for sensitive data
function Scan-File {
    param(
        [string]$file
    )

    try {
        # Process the file line by line to reduce memory usage
        Get-Content -Path $file -ReadCount 0 | ForEach-Object {
            $line = $_
            # Check each pattern against the line
            foreach ($pattern in $patterns) {
                if ($line -match $pattern) {
                    # Write the matched content to the output file
                    Add-Content -Path $outputFile -Value "Match found in ${file}: $($matches[0])"
                }
            }
        }
    }
    catch {
        # Handle any errors (e.g., access denied)
        Write-Output "Could not read file: $file - $_"
    }
}

# Total files to scan (for progress bar calculation)
$totalFiles = 0
foreach ($drive in $drives) {
    $totalFiles += (Get-ChildItem -Path $drive.Root -Recurse -ErrorAction SilentlyContinue -Force | Measure-Object).Count
}

# Progress bar initialization
$currentFileCount = 0

# Scan each drive
foreach ($drive in $drives) {
    Write-Output "Scanning drive: $($drive.Name)"
    # Recursively get all files on the drive, ignoring errors
    $files = Get-ChildItem -Path $drive.Root -Recurse -ErrorAction SilentlyContinue -Force

    foreach ($file in $files) {
        # Update progress bar
        $currentFileCount++
        Write-Progress -Activity "Scanning Files" -Status "$currentFileCount of $totalFiles files" -PercentComplete (($currentFileCount / $totalFiles) * 100)

        # Filter only text-based files for scanning
        if ($file.Extension -in ".txt", ".csv", ".log", ".xml", ".json", ".html", ".md") {
            Scan-File -file $file.FullName
        }
    }
}

Write-Output "Scan completed. Results saved to $outputFile"
