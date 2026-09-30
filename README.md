# Splunk Detection Lab

Detections for a real simulated attack, built in Splunk and documented as code.

I loaded Windows event logs from an attacker using Empire and Mimikatz to steal credentials, checked the data parsed correctly, then wrote and tuned four detections mapped to MITRE ATT&CK. Each detection started broad, and I narrowed it by looking at what normal Windows activity was also matching.

![Detection dashboard](images/dashboard.png)

## The attack

Dataset: [OTRF Security-Datasets, `empire_mimikatz_logonpasswords`](https://github.com/OTRF/Security-Datasets/tree/master/datasets/atomic/windows/credential_access/host). 6,026 events from about 3 minutes on August 7, 2020 (Sysmon, Windows Security and PowerShell logs).

| Time (UTC) | What the attacker did | Detection |
| --- | --- | --- |
| 14:32:46 | Started PowerShell with an encoded (base64) command | DL-002 |
| 14:32:47 onward | PowerShell checked in with its C2 server at 10.10.10.5:80 about every 5 seconds | DL-004 |
| 14:32:57.58 | PowerShell loaded 10 credential-related DLLs in 7 ms (Mimikatz starting up) | DL-003 |
| 14:32:57.59 | PowerShell opened lsass.exe with permission to read its memory | DL-001 |

## Detections

| ID | Detection | ATT&CK | Log source | Hits before tuning | After |
| --- | --- | --- | --- | --- | --- |
| [DL-001](detections/T1003.001_lsass_memory_access.yml) | LSASS memory access | T1003.001 | Sysmon 10 | 4 | 1 |
| [DL-002](detections/T1059.001_encoded_powershell.yml) | Encoded PowerShell | T1059.001 | PowerShell 400 | 1 | 1 |
| [DL-003](detections/T1003.001_mimikatz_dll_loads.yml) | Mimikatz DLL loads | T1003.001 | Sysmon 7 | 3 processes | 1 |
| [DL-004](detections/T1071.001_c2_beaconing.yml) | C2 beaconing | T1071.001 | Sysmon 3 | 2 | 1 |

Each file has the SPL, how it works, false positives (seen in testing and expected in production), what I changed while tuning and why, test results, and known blind spots.

A few things I learned while tuning:

- **LSASS access alone is noise.** 3 of 4 hits were svchost asking for harmless permissions. Checking for the read-memory bit (0x10) and for calls from code with no file on disk (`UNKNOWN` in the CallTrace) left only Mimikatz.
- **The combination is the signal.** Every DLL Mimikatz loads is a normal, signed Windows file. One process loading 10 of them in 7 ms is not.
- **Regular traffic isn't always malicious.** A Windows service (ADWS) called out more regularly than the malware, because attackers add jitter on purpose. What ruled it out was the destination: it was talking to itself over loopback.
- **Check the data exists before writing the search.** My first idea for DL-002 used process creation events, but the attacker's PowerShell started before logging began, so that search returned nothing.

## Data validation

Before writing detections I checked the data loaded correctly. Two Splunk defaults were quietly breaking it:

- `MAX_DAYS_AGO` defaults to 2,000 days, so every 2020 event was stamped with today's date. Caught by comparing `_time` to the raw `@timestamp`.
- `TRUNCATE` defaults to 10,000 characters, and 29% of events were longer than that.

Full checks and fixes: [data-validation.md](data-validation.md). Sourcetype config: [props.conf](props.conf).

## Repo layout

```
.
├── README.md
├── data-validation.md      validation searches, results and parsing fixes
├── props.conf              sourcetype config used to load the data
├── dashboards/
│   └── detection_lab.xml   Splunk dashboard source
├── detections/             one YAML file per detection
└── images/
```

## Run it yourself

1. Download `empire_mimikatz_logonpasswords.zip` from the OTRF link above and unzip it.
2. In Splunk, create an index called `otrf` and a sourcetype using the settings in `props.conf`.
3. Upload the JSON file to that index. `index=otrf | stats count` should return 6,026 (set the time range to All time).
4. Run the `search` from any detection file. To load the dashboard, create a new Classic dashboard, open **Source**, and paste in `dashboards/detection_lab.xml`.

## Limits

- One dataset, about 3 minutes long. Thresholds haven't been tested against a real environment's normal activity.
- I planned to add account creation and scheduled task detections from other OTRF datasets, but Windows Defender flags those files (they contain real attack strings), so I kept the lab to this one.
- Not covered: dump-to-file methods (ProcDump, comsvcs.dll), malicious Security Support Providers (T1547.005), and attackers who avoid PowerShell.

## Tools

Splunk Enterprise (trial), SPL, Sysmon and Windows event logs, MITRE ATT&CK, YAML, Git and GitHub.
