# monitor.ps1
Write-Host "Python Process Monitor for Titanium Scanner" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Cyan

$counter = 1
while ($true) {
    Clear-Host
    $now = Get-Date -Format 'HH:mm:ss'
    Write-Host "Scan: $counter - Time: $now" -ForegroundColor Yellow
    Write-Host "------------------------------------------------------------" -ForegroundColor Gray
    
    $processes = Get-Process python* -ErrorAction SilentlyContinue
    
    if (-not $processes) {
        Write-Host "No Python processes found" -ForegroundColor Red
    }
    else {
        $count = $processes.Count
        if ($null -eq $count) { $count = 1 }
        
        Write-Host "Found $count Python process(es)" -ForegroundColor Green
        
        foreach ($p in $processes) {
            $cpu = $p.CPU
            $mem = [math]::Round($p.WorkingSet / 1MB, 2)
            $pid_num = $p.Id
            $name = $p.Name
            
            Write-Host ""
            Write-Host "Process: $name (PID: $pid_num)" -ForegroundColor Cyan
            Write-Host "   CPU: $cpu s"
            Write-Host "   Mem: $mem MB"
            
            if ($p.Responding) {
                Write-Host "   Status: Running" -ForegroundColor Green
            }
            else {
                Write-Host "   Status: Not Responding" -ForegroundColor Red
            }
        }
        
        Write-Host ""
        Write-Host "Network Connections:" -ForegroundColor Cyan
        try {
            # Try getting connections for the first process as an example/check
            # Iterate through processes to get IDs properly
            $ids = @($processes) | ForEach-Object { $_.Id }
            $connections = Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object { $ids -contains $_.OwningProcess }
            
            if ($connections) {
                $connections | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State | Format-Table -AutoSize
            }
            else {
                Write-Host "   No active network connections" -ForegroundColor Gray
            }
        }
        catch {
            Write-Host "   Cannot check connections (may need Admin)" -ForegroundColor Yellow
        }
    }
    
    Write-Host ""
    Write-Host "New Files Created (Last 5 mins):" -ForegroundColor Cyan
    $recentFiles = Get-ChildItem -Path . -Filter "*.json" -File | Where-Object { $_.LastWriteTime -gt (Get-Date).AddMinutes(-5) }
    
    if ($recentFiles) {
        foreach ($f in $recentFiles) {
            $kb = [math]::Round($f.Length / 1KB, 2)
            $time = $f.LastWriteTime.ToString('HH:mm:ss')
            Write-Host "   $($f.Name) - $time - $kb KB" -ForegroundColor Green
        }
    }
    else {
        Write-Host "   No new JSON files." -ForegroundColor Gray
    }
    
    $counter++
    Start-Sleep -Seconds 3
}