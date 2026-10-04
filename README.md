<h1 align="center">SYN-ACK Check</h1>

<p align="center">
  TCP handshake checker for network troubleshooting.
</p>

---

A Windows PowerShell GUI for inspecting a single outbound TCP connection.

## Install

You need Windows 11 or Windows Server 2025, Windows PowerShell 5.1 and administrator rights. Pktmon and NetTCPIP are built into Windows; no additional packages are required.

Save `Test-TcpHandshake.ps1`, open Windows PowerShell as administrator, and run:

```powershell
powershell.exe -NoProfile -STA -File .\Test-TcpHandshake.ps1
```

## What it does

Starts a short Pktmon capture, attempts a TCP connection and matches the SYN → SYN-ACK → ACK flow using sequence and acknowledgment numbers. Shows the connection result, packet details and a filtered PCAPNG saved under `%LOCALAPPDATA%\TcpHandshake-*`.

## Output

Screenshots from the native Windows 11 validation.

**Ready.** Enter the destination IPv4 address and TCP port.

![GUI ready for a TCP handshake test](assets/gui-ready.png)

**Capturing.** The test runs in the background; **Run test** remains disabled until it finishes.

![GUI while capturing and testing](assets/gui-capturing.png)

**Completed.** `Handshake` reports the verdict. `SYN`, `SYN-ACK` and `ACK` show matched steps as `True` or `False`; `False` means the capture did not confirm that step.

![GUI showing a confirmed SYN, SYN-ACK and ACK flow](assets/gui-result.png)

## Demo

Enter `1.1.1.1` and port `443`, then select **Run test**. **Copy result** copies the diagnostic text. Use the source port and start time to correlate the test with firewall logs.

## Scope and limits

- One outbound IPv4 test, with an eight-second TCP connect timeout; no TLS or application checks.
- VPNs, Pktmon filters and missing packets can limit local evidence. Missing packets do not establish a firewall block.
- Avoid concurrent Pktmon sessions. Delete retained captures when finished; forced termination can leave sensitive raw files.
