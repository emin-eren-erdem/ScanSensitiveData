# Sensitive Data Scanner

This PowerShell script scans all drives on your system for potential sensitive information, such as credit card numbers, social security numbers, email addresses, and API keys. The results are saved to a file (`C:\ScanResults.txt`).

## Features

- Scans all logical drives on your system.
- Matches common patterns for credit card numbers, social security numbers, email addresses, and more.
- Saves results to a specified output file.
- Filters only text-based files to improve performance.

## Performance and User Experience Enhancements

- **Progress Bar**: The script includes a progress bar to provide real-time feedback on the scanning progress. This makes it easier for users to see what's happening during the scan.
- **Reduced Memory Usage**: To improve performance, the script processes files line by line instead of loading the entire file into memory. This significantly reduces the RAM usage, making the scan more efficient, especially for large files.
- **User-Friendly Output**: The script outputs the current drive being scanned and keeps the user informed about the progress, making the tool more user-friendly.

## Usage

1. Clone this repository to your local machine.
2. Open PowerShell with administrative privileges.
3. Run the script using the following command:

   ```powershell
   .\ScanSensitiveData.ps1

4. Once the scan is complete, review the results in the C:\ScanResults.txt file.
