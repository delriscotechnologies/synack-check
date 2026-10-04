$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { throw 'This script requires Windows.' }
Add-Type -AssemblyName PresentationFramework
if ([Threading.Thread]::CurrentThread.ApartmentState -ne 'STA') { throw 'Run powershell.exe -NoProfile -STA -File .\Test-TcpHandshake.ps1' }
$admin = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $admin.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Open PowerShell as administrator first.' }
$pktmon = Join-Path ([Environment]::GetFolderPath('System')) 'pktmon.exe'
if (-not (Test-Path -LiteralPath $pktmon)) { throw 'Pktmon is unavailable on this Windows installation.' }
$worker = {
    param($Target, $Port, $Pktmon)
    $ErrorActionPreference = 'Stop'
    function Invoke-Pktmon {
        $message = & $Pktmon @args 2>&1
        if ($LASTEXITCODE -ne 0) { throw "Pktmon $($args[0]) failed: $($message -join "`n")`nCheck pktmon status before retrying. Files: $folder" }
    }
    function Read-Packets($Path, $FlowPath) {
        if ([IO.FileInfo]::new($Path).Length -gt 67108864) { throw 'Capture exceeds the 64 MB analysis limit.' }
        $bytes = [IO.File]::ReadAllBytes($Path)
        if ($bytes.Length -lt 28 -or [BitConverter]::ToUInt32($bytes, 0) -ne 0x0A0D0D0A) { throw 'Invalid capture section.' }
        $links = [Collections.Generic.List[uint16]]::new()
        $matched = 0
        $writer = [IO.File]::Open($FlowPath + '.partial', [IO.FileMode]::CreateNew)
        try { for ($offset = 0; $offset -lt $bytes.Length; $offset += $length) {
            if ($bytes.Length - $offset -lt 12) { throw 'Truncated capture block.' }
            $type = [BitConverter]::ToUInt32($bytes, $offset)
            $length = [BitConverter]::ToUInt32($bytes, $offset + 4)
            if ($length -lt 12 -or $length % 4 -or $length -gt $bytes.Length - $offset) { throw 'Invalid capture block.' }
            if ([BitConverter]::ToUInt32($bytes, $offset + $length - 4) -ne $length) { throw 'Invalid capture block trailer.' }
            if ($type -eq 0x0A0D0D0A) {
                if ($length -lt 28 -or [BitConverter]::ToUInt32($bytes, $offset + 8) -ne 0x1A2B3C4D -or [BitConverter]::ToUInt16($bytes, $offset + 12) -ne 1) { throw 'Unsupported capture section.' }
                $links.Clear()
            }
            if ($type -eq 1) {
                if ($length -lt 20) { throw 'Invalid capture interface.' }
                $links.Add([BitConverter]::ToUInt16($bytes, $offset + 8))
            }
            if ($type -in @(1, 0x0A0D0D0A)) { $writer.Write($bytes, $offset, $length) }
            if ($type -ne 6) { continue }
            if ($length -lt 32) { throw 'Invalid packet block.' }
            $interface = [BitConverter]::ToUInt32($bytes, $offset + 8)
            if ($interface -ge $links.Count -or $links[$interface] -ne 1) { throw 'Only Ethernet captures are supported.' }
            $size = [BitConverter]::ToUInt32($bytes, $offset + 20)
            $originalSize = [BitConverter]::ToUInt32($bytes, $offset + 24)
            if ($size -gt $length - 32 -or $size -gt $originalSize) { throw 'Invalid captured packet length.' }
            $start = $offset + 28
            $end = $start + $size
            if ($size -lt 14) { continue }
            $ip = $start + 14
            $etherType = $bytes[$ip - 2] * 256 + $bytes[$ip - 1]
            while ($etherType -in @(0x8100, 0x88A8) -and $ip + 4 -le $end) {
                $ip += 4
                $etherType = $bytes[$ip - 2] * 256 + $bytes[$ip - 1]
            }
            if ($etherType -ne 0x0800 -or $ip + 20 -gt $end -or ($bytes[$ip] -shr 4) -ne 4) { continue }
            $header = ($bytes[$ip] -band 15) * 4
            $total = $bytes[$ip + 2] * 256 + $bytes[$ip + 3]
            if ($header -lt 20 -or $ip + $total -gt $start + $originalSize -or $bytes[$ip + 9] -ne 6) { continue }
            if (($bytes[$ip + 6] * 256 + $bytes[$ip + 7]) -band 0x3FFF) { continue }
            $tcp = $ip + $header
            if ($tcp + 20 -gt $end) { continue }
            $tcpHeader = ($bytes[$tcp + 12] -shr 4) * 4
            if ($tcpHeader -lt 20 -or $total -lt $header + $tcpHeader -or $tcp + $tcpHeader -gt $end) { continue }
            $source = $bytes[($ip + 12)..($ip + 15)] -join '.'
            $destination = $bytes[($ip + 16)..($ip + 19)] -join '.'
            $sourcePort = $bytes[$tcp] * 256 + $bytes[$tcp + 1]
            $destinationPort = $bytes[$tcp + 2] * 256 + $bytes[$tcp + 3]
            $outbound = $source -eq $localAddress -and $sourcePort -eq $localPort -and $destination -eq $Target -and $destinationPort -eq $Port
            if (-not $outbound -and -not ($source -eq $Target -and $sourcePort -eq $Port -and $destination -eq $localAddress -and $destinationPort -eq $localPort)) { continue }
            if (++$matched -gt 512) { throw 'More than 512 matching packets; analysis stopped.' }
            $sequence = [uint64]$bytes[$tcp + 4] * 16777216 + $bytes[$tcp + 5] * 65536 + $bytes[$tcp + 6] * 256 + $bytes[$tcp + 7]
            $ack = [uint64]$bytes[$tcp + 8] * 16777216 + $bytes[$tcp + 9] * 65536 + $bytes[$tcp + 10] * 256 + $bytes[$tcp + 11]
            [pscustomobject]@{
                Outbound = $outbound; Flags = $bytes[$tcp + 13]; Sequence = $sequence; Ack = $ack; Index = $matched
                Next = ($sequence + $total - $header - $tcpHeader + [int][bool]($bytes[$tcp + 13] -band 2)) % 4294967296
            }
            $writer.Write($bytes, $offset, $length)
        } } finally { $writer.Dispose() }
        [IO.File]::Move($FlowPath + '.partial', $FlowPath)
    }
    $capturing = $false; $client = $null
    $folder = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) ('TcpHandshake-' + [guid]::NewGuid().ToString('N'))
    $etl, $pcap, $flow = 'capture.etl', 'capture.pcapng', 'flow.pcapng' | ForEach-Object { Join-Path $folder $_ }
    try {
        $null = New-Item -ItemType Directory -Path $folder
        $acl = [Security.AccessControl.DirectorySecurity]::new()
        $acl.SetSecurityDescriptorSddlForm('D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;' + [Security.Principal.WindowsIdentity]::GetCurrent().User.Value + ')')
        Set-Acl -LiteralPath $folder -AclObject $acl
        try {
            $client = [Net.Sockets.TcpClient]::new([Net.Sockets.AddressFamily]::InterNetwork)
            Import-Module (Join-Path ([Environment]::GetFolderPath('System')) 'WindowsPowerShell\v1.0\Modules\NetTCPIP\NetTCPIP.psd1')
            $localAddress = Find-NetRoute -RemoteIPAddress $Target | Where-Object IPAddress | Select-Object -ExpandProperty IPAddress -First 1
            if ($localAddress -eq $Target) { throw 'Choose another computer; local connections may bypass the NIC capture.' }
            $client.Client.Bind([Net.IPEndPoint]::new([Net.IPAddress]::Parse($localAddress), 0))
            $localPort = $client.Client.LocalEndPoint.Port
            Invoke-Pktmon start --capture --comp nics --pkt-size 128 --file-size 16 --log-mode circular --file-name $etl
            $capturing = $true
            $started = [DateTimeOffset]::Now.ToString('yyyy-MM-dd HH:mm:ss zzz')
            $connection = 'Timed out after 8 seconds'
            try { if ($client.ConnectAsync([Net.IPAddress]::Parse($Target), $Port).Wait(8000)) { $connection = 'Connected' } }
            catch { $connection = $_.Exception.GetBaseException().Message }
            Start-Sleep -Milliseconds 250
        } finally {
            try { if ($capturing) { Invoke-Pktmon stop; $capturing = $false } }
            finally { if ($client) { $client.Dispose() } }
        }
        Invoke-Pktmon etl2pcap $etl --out $pcap
        $packets = @(Read-Packets $pcap $flow)
        $syn = $packets | Where-Object { $_.Outbound -and ($_.Flags -band 0x17) -eq 2 } | Select-Object -First 1
        $synAck = $packets | Where-Object {
            $syn -and -not $_.Outbound -and $_.Index -gt $syn.Index -and ($_.Flags -band 0x17) -eq 0x12 -and $_.Ack -eq $syn.Next
        } | Select-Object -First 1
        $ack = $packets | Where-Object {
            $synAck -and $_.Outbound -and $_.Index -gt $synAck.Index -and ($_.Flags -band 0x17) -eq 0x10 -and
            $_.Sequence -eq $synAck.Ack -and $_.Ack -eq $synAck.Next
        } | Select-Object -First 1
        $verdict = if ($ack) { 'Yes; SYN -> SYN-ACK -> ACK confirmed locally' }
        elseif ($connection -eq 'Connected') { 'Yes; TCP connect succeeded; packet evidence incomplete' }
        elseif ($packets.Where({ -not $_.Outbound -and ($_.Flags -band 4) })) { 'Incoming RST observed; handshake not confirmed' }
        elseif ($synAck) { 'SYN and SYN-ACK matched; final ACK not confirmed' }
        elseif ($syn) { 'Not confirmed; SYN observed; no matching SYN-ACK' }
        else { 'Inconclusive: no matching SYN captured' }
        $lines = @("Handshake   $verdict", "Started     $started", "Source      ${localAddress}:$localPort", "Target      ${Target}:$Port", "TCP connect $connection", '')
        $lines += "SYN         $([bool]$syn)", "SYN-ACK     $([bool]$synAck)", "ACK         $([bool]$ack)", ''
        foreach ($packet in $packets) {
            $flags = for ($bit = 0; $bit -lt 8; $bit++) { if ($packet.Flags -band (1 -shl $bit)) { @('FIN', 'SYN', 'RST', 'PSH', 'ACK', 'URG', 'ECE', 'CWR')[$bit] } }
            $lines += '{0,3} {1,-3} {2,-15} SEQ={3} ACK={4}' -f $packet.Index, @('IN', 'OUT')[[int]$packet.Outbound], ($flags -join ','), $packet.Sequence, $packet.Ack
        }
        $lines += '', "Capture     $flow"
        $lines -join "`r`n"
    } finally {
        if (-not $capturing) { foreach ($file in @($etl, $pcap, ($flow + '.partial'))) { if (Test-Path -LiteralPath $file) { Remove-Item -LiteralPath $file } } }
    }
}
[xml]$xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml" Title="SYN-ACK Check" Width="660" Height="520" MinWidth="540" MinHeight="420" Background="#181818" Foreground="#E8E8E8" FontFamily="Segoe UI" WindowStartupLocation="CenterScreen">
  <Window.Resources><ControlTemplate x:Key="DarkButton" TargetType="Button"><Border Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="1" Padding="{TemplateBinding Padding}"><ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/></Border><ControlTemplate.Triggers><Trigger Property="IsEnabled" Value="False"><Setter Property="Opacity" Value="0.45"/></Trigger><Trigger Property="IsPressed" Value="True"><Setter Property="Opacity" Value="0.75"/></Trigger></ControlTemplate.Triggers></ControlTemplate></Window.Resources>
  <Grid Margin="24">
    <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
    <TextBlock Text="SYN-ACK Check" FontSize="24" FontWeight="SemiBold" Margin="0,0,0,18"/>
    <Grid Grid.Row="1" Margin="0,0,0,18">
      <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="110"/><ColumnDefinition Width="120"/></Grid.ColumnDefinitions>
      <StackPanel Margin="0,0,12,0"><Label Content="Target IPv4" Foreground="#E8E8E8" Target="{Binding ElementName=Target}" Padding="0,0,0,6"/><TextBox Name="Target" MaxLength="15" Padding="9" FontSize="14"/></StackPanel>
      <StackPanel Grid.Column="1" Margin="0,0,12,0"><Label Content="TCP port" Foreground="#E8E8E8" Target="{Binding ElementName=Port}" Padding="0,0,0,6"/><TextBox Name="Port" MaxLength="5" Text="443" Padding="9" FontSize="14"/></StackPanel>
      <Button Name="Run" Grid.Column="2" Content="Run test" Template="{StaticResource DarkButton}" VerticalAlignment="Bottom" Padding="10" IsDefault="True"/>
    </Grid>
    <TextBox Name="Result" Grid.Row="2" IsReadOnly="True" TextWrapping="Wrap" VerticalScrollBarVisibility="Auto" Padding="14" FontFamily="Consolas" Text="Enter a destination and run a test."/>
    <DockPanel Grid.Row="3" Margin="0,14,0,0"><Button Name="Copy" Content="Copy result" Template="{StaticResource DarkButton}" Padding="12,7" DockPanel.Dock="Right"/><TextBlock Name="Status" Text="Ready" VerticalAlignment="Center"/></DockPanel>
  </Grid>
</Window>
'@
$window = [Windows.Markup.XamlReader]::Load([Xml.XmlNodeReader]::new($xaml))
$targetInput, $portInput, $run, $result, $copy, $status = 'Target', 'Port', 'Run', 'Result', 'Copy', 'Status' | ForEach-Object { $window.FindName($_) }
foreach ($control in @($targetInput, $portInput, $run, $result, $copy)) { $control.Background = '#252525'; $control.Foreground = '#E8E8E8'; $control.BorderBrush = '#555555' }
$timer = [Windows.Threading.DispatcherTimer]::new()
$timer.Interval = [TimeSpan]::FromMilliseconds(150)
$script:job = $null
$run.Add_Click({
    $address, $number = $null, 0
    if ($targetInput.Text.Trim() -notmatch '^(?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){3}$' -or
        -not [Net.IPAddress]::TryParse($targetInput.Text.Trim(), [ref]$address) -or [Net.IPAddress]::IsLoopback($address) -or
        $address.GetAddressBytes()[0] -eq 0 -or $address.GetAddressBytes()[0] -ge 224) {
        $status.Text = 'Enter a remote unicast IPv4 address.'; return
    }
    if (-not [int]::TryParse($portInput.Text, [ref]$number) -or $number -lt 1 -or $number -gt 65535) { $status.Text = 'Enter a port from 1 to 65535.'; return }
    $run.IsEnabled = $false
    $status.Text = 'Capturing and testing…'
    $result.Text = ''
    try {
        $script:job = [PowerShell]::Create()
        $null = $script:job.AddScript($worker.ToString()).AddArgument($address.ToString()).AddArgument($number).AddArgument($pktmon)
        $script:pendingJob = $script:job.BeginInvoke()
        $timer.Start()
    } catch {
        if ($script:job) { $script:job.Dispose(); $script:job = $null }
        $result.Text = $_.Exception.Message; $status.Text = 'Failed'; $run.IsEnabled = $true
    }
})
$timer.Add_Tick({
    if (-not $script:pendingJob.IsCompleted) { return }
    $timer.Stop()
    try {
        $result.Text = ($script:job.EndInvoke($script:pendingJob) -join "`r`n")
        $status.Text = 'Finished'
    } catch { $result.Text = $_.Exception.GetBaseException().Message; $status.Text = 'Failed' }
    finally { $script:job.Dispose(); $script:job = $null; $run.IsEnabled = $true }
})
$copy.Add_Click({ try { [Windows.Clipboard]::SetText($result.Text); $status.Text = 'Copied' } catch { $status.Text = 'Clipboard unavailable' } })
$window.Add_Closing({ param($sender, $eventArgs) if ($script:job) { $eventArgs.Cancel = $true; $status.Text = 'Wait for the capture to finish before closing.' } })
$null = $window.ShowDialog()
