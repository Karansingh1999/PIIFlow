# Demo Scripts

PIIFlow includes repository-relative demo scripts for Bash and PowerShell:

```bash
scripts/demo.sh
```

```powershell
.\scripts\demo.ps1
```

If local execution policy blocks scripts, use a process-scoped bypass:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\demo.ps1
```

The scripts do not use API keys, make network calls, or execute target
application code. They run PIIFlow against synthetic example source files.

## Demonstrations

| Demo | Expected exit code | Meaning |
| --- | ---: | --- |
| Safe application | 0 | Only non-failing informational output is reported. |
| Vulnerable application | 1 | Sensitive flows meet the default failing threshold. |
| Compliant redacted-email policy flow | 0 | Email reaches OpenAI with required sanitizer evidence. |
| Wrong sanitizer policy violation | 1 | A sanitizer was observed, but not the one required by policy. |
| Local financial allow rule | 0 | Financial data reaches a local sink allowed by policy. |
| JSON output | 0 | A policy-compliant report is written under `.tmp/demo/`. |

Exit code `1` is expected for the vulnerable and wrong-sanitizer cases. The
scripts fail only when a command returns a different exit code than expected.
