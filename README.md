<h1 align="center">SYN-ACK Check</h1>

<p align="center">
  TCP handshake checker for network troubleshooting.
</p>

---

Check a TCP handshake from Windows. The dark GUI shows SYN, SYN-ACK and ACK as `True` or `False`, reports completion, displays packet details and saves the tested flow as PCAPNG.

## Install

You need Windows 11, Windows PowerShell 5.1, administrator rights, and the built-in Pktmon and NetTCPIP tools. No additional packages are required.

Save `Test-TcpHandshake.ps1`, open Windows PowerShell as administrator, and run:

```powershell
powershell.exe -NoProfile -STA -File .\Test-TcpHandshake.ps1
```

Enter the destination IPv4 address and TCP port, then select **Run test**. **Copy result** copies the diagnostic text.

## Results

Example of a complete handshake:

```text
Handshake   Yes; SYN -> SYN-ACK -> ACK confirmed locally
Source      10.20.10.15:51432
Target      10.20.30.40:443
TCP connect Connected

SYN         True
SYN-ACK     True
ACK         True

  1 OUT SYN             SEQ=100 ACK=0
  2 IN  SYN,ACK         SEQ=200 ACK=101
  3 OUT ACK             SEQ=101 ACK=201
```

`OUT` means sent; `IN` means received. `True` confirms a step matching the preceding steps; `False` means it was not confirmed. A SYN-ACK without a captured SYN stays `False`, even when its flags appear in the packet list. `Handshake` reports completion separately and identifies incomplete capture evidence when TCP connect succeeds. Rows follow capture order; repeated rows may be duplicate observations.

| Result | Meaning |
| --- | --- |
| Yes; SYN → SYN-ACK → ACK confirmed locally | All three matching steps were captured locally. |
| Yes; TCP connect succeeded; packet evidence incomplete | Windows completed the connection, but the capture cannot confirm every step. |
| Incoming RST observed; handshake not confirmed | A reset was received in the tested flow. Its origin and acceptance by the TCP stack are not established. |
| SYN and SYN-ACK matched; final ACK not confirmed | The first two steps match; the final matching ACK is absent. |
| Not confirmed; SYN observed; no matching SYN-ACK | A SYN was captured without a matching response. |
| Inconclusive: no matching SYN captured | The capture provides insufficient evidence for this test. |

Correlate the source port and start time with firewall logs. Matching packets are saved as `flow.pcapng` in a private `TcpHandshake-*` folder under `%LOCALAPPDATA%`.

## Limitations

- Tests one ordinary outbound IPv4 handshake and waits up to eight seconds for TCP connect; capture setup, stopping and conversion take additional time. Supports little-endian Ethernet PCAPNG, VLAN tags and unfragmented IPv4.
- Evidence is local: missing packets do not prove a firewall block. No TLS, application checks, other-application monitoring or proof of final ACK delivery; packets are not authenticated.
- Avoid concurrent Pktmon sessions. Existing filters and VPN encapsulation can affect visibility. Capture is limited to a 16 MB circular log and 128 bytes per packet; analysis stops above 64 MiB or 512 matching packets.
- Capture briefly includes other traffic. Raw files are removed after stopping; forced termination or stop failure can leave them behind. Delete retained captures when no longer needed; inspect `pktmon status` if stopping fails.

Validated with 36 synthetic checks and six simulated capture scenarios on Linux. Native Windows capture, GUI and permissions still need verification with an open, closed and silently filtered remote port.

## Security

Validates addresses and ports, uses Pktmon's system path with separate arguments, bounds packet processing and restricts capture folders to the current user and SYSTEM. It only stops capture after its own start succeeds. Captures may contain sensitive data; the review does not guarantee zero vulnerabilities.

## References

[Pktmon capture](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/pktmon-start) · [PCAPNG conversion](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/pktmon-etl2pcap) · [TCP specification](https://www.rfc-editor.org/rfc/rfc9293.html)
