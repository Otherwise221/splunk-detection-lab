# Data Validation: OTRF empire_mimikatz_logonpasswords

## Dataset
- Source: [OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets), `datasets/atomic/windows/credential_access/host/empire_mimikatz_logonpasswords.zip`
- Simulates: Empire PowerShell agent running Mimikatz `sekurlsa::logonpasswords` against LSASS
- Relevant ATT&CK techniques: T1003.001 (LSASS Memory), T1059.001 (PowerShell)
- Log sources: Sysmon, Windows Security, Windows PowerShell, PowerShell/Operational
- Loaded into index `otrf` with sourcetype `otrf:json` (see `props.conf`)

## Validation results
All searches run with time range set to All time.

| Check | Search | Expected | Result |
|---|---|---|---|
| Event count | `index=otrf \| stats count` | 6,026 | 6,026 ✅ |
| Time range | `index=otrf \| stats min(_time) as first max(_time) as last \| convert ctime(first) ctime(last)` | 2020-08-07, about 3 minutes | 10:32:25.358 to 10:35:26.113 (Eastern; 14:32 to 14:35 UTC) ✅ |
| No truncation | `index=otrf \| eval len=len(_raw) \| stats max(len)` | Longer than 10,000 | 21,669 ✅ |
| No broken JSON | `index=otrf \| where isnull(EventID) \| stats count` | 0 | 0 ✅ |
| Source coverage | `index=otrf \| stats count by Channel EventID \| sort -count` | PowerShell 800/4103 highest, Sysmon 10 present | 34 Channel/EventID combinations ✅ |
| Key fields parse | `index=otrf EventID=10 TargetImage="*lsass.exe" \| table _time SourceImage TargetImage GrantedAccess` | 4 rows | 4 rows ✅ |

## Issues found and fixed

### 1. Events would have been truncated
1,747 of 6,026 events (29%) are longer than 10,000 characters, Splunk's default `TRUNCATE` limit. Truncated events would have broken JSON and missing fields. Fixed with `TRUNCATE = 0`.

### 2. Every event got the wrong date
In the upload preview, `_time` showed the correct time of day but today's date, with a "failed to parse timestamp" warning. Splunk was reading `@timestamp` correctly but rejecting it because it was older than the default `MAX_DAYS_AGO` of 2,000 days (the data is from August 2020). Caught by comparing `_time` against the raw `@timestamp` field. Fixed with `MAX_DAYS_AGO = 10951`.

### 3. Indexed vs. search-time JSON extraction
Kept `INDEXED_EXTRACTIONS = json` rather than search-time extraction. In 1,744 of the long events, the `EventID` field appears after character 10,240, which is the default limit for search-time field extraction. Search-time parsing would have silently dropped `EventID` on those events. `KV_MODE = none` prevents fields from being extracted twice.

## Notes
- The `host` field is the machine that loaded the file. The original source host is in the `Hostname` field (for example `MORDORDC.theshire.local`), and detections use that.
- Initial look at LSASS access: 3 events from `svchost.exe` with limited query rights (0x1000, 0x2000) and 1 from `powershell.exe` with 0x1010 (includes PROCESS_VM_READ). The PowerShell event is the Mimikatz activity; the svchost events are expected Windows behavior. This drives the tuning in the T1003.001 detection.
