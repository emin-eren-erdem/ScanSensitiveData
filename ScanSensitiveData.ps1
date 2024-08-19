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
        # Read file content as string
        $content = Get-Content -Path $file -Raw -ErrorAction Stop

        # Check each pattern against the content
        foreach ($pattern in $patterns) {
            if ($content -match $pattern) {
                # Write the matched content to the output file
                Add-Content -Path $outputFile -Value "Match found in ${file}: $($matches[0])"
            }
        }
    }
    catch {
        # Handle any errors (e.g., access denied)
        Write-Output "Could not read file: $file - $_"
    }
}

# Scan each drive
foreach ($drive in $drives) {
    # Recursively get all files on the drive, ignoring errors
    $files = Get-ChildItem -Path $drive.Root -Recurse -ErrorAction SilentlyContinue -Force

    foreach ($file in $files) {
        # Filter only text-based files for scanning
        if ($file.Extension -in ".txt", ".csv", ".log", ".xml", ".json", ".html", ".md") {
            Scan-File -file $file.FullName
        }
    }
}

Write-Output "Scan completed. Results saved to $outputFile"
