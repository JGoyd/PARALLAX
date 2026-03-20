# PARALLAX -- iOS Reality Detection

Browser-based sysdiagnose analyzer for detecting exploitation indicators on iOS devices. No install, no dependencies -- drag and drop your sysdiagnose and get results.

**Live tool: [https://jgoyd.github.io/PARALLAX](https://jgoyd.github.io/PARALLAX)**

## How to Use

1. Generate a sysdiagnose on your iPhone:
   - Settings > Privacy & Security > Analytics & Improvements > sysdiagnose
   - Or hold Volume Up + Down + Power for 1.5 seconds
   - Wait ~10 minutes, then find it in Analytics Data
2. Open PARALLAX in any browser (or use the live link above)
3. Drag and drop your sysdiagnose .tar.gz
4. Review results

Runs entirely in your browser. No data leaves your machine.

## What It Detects

PARALLAX scans sysdiagnose files for indicators across multiple exploitation layers: hardware/firmware manipulation, baseband redirection, persistence mechanisms, unauthorized data collection, and egress channels.

## Related

- [AzulMalla](https://github.com/JGoyd/AzulMalla) -- BCM43xx coexistence SRAM vulnerability disclosure and `mesh_detect.py` CLI scanner
