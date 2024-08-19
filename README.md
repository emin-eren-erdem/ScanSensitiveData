# Sensitive Data Scanner

This PowerShell script scans all drives on your system for potential sensitive information, such as credit card numbers, social security numbers, email addresses, and API keys. The results are saved to a file (`C:\ScanResults.txt`).

## Features

- Scans all logical drives on your system.
- Matches common patterns for credit card numbers, social security numbers, email addresses, and more.
- Saves results to a specified output file.
- Filters only text-based files to improve performance.

## Usage

1. Clone this repository to your local machine.
2. Open PowerShell with administrative privileges.
3. Run the script using the following command:

   ```powershell
   .\ScanSensitiveData.ps1

4. Once the scan is complete, review the results in the C:\ScanResults.txt file.
