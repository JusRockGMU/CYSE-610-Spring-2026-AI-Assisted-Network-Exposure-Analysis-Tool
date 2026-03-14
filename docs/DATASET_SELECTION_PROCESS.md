# Dataset Selection Process Documentation

**Date:** March 14, 2026  
**Purpose:** Document how we evaluated and selected our final dataset for the project

---

## Selection Criteria

We needed a dataset with:
1. Real nmap scan data (XML format preferred)
2. Known vulnerabilities for validation
3. Multiple targets for comprehensive testing
4. Publicly available and citable
5. Recent scans with current vulnerability landscape

---

## Datasets Evaluated

We tested **4 public datasets** from our project plan:

### 1. InfoSecWarrior/Vulnerable-Box-Resources  SELECTED
- **Source:** https://github.com/InfoSecWarrior/Vulnerable-Box-Resources
- **Content:** 822 nmap scans (274 XML + 548 text) across 11 targets
- **Quality:**  Excellent
- **Scan Date:** September 2024
- **Verdict:** **SELECTED** - Best option with complete data

**Why Selected:**
- Real nmap scans from actual vulnerable systems
- Multiple diverse targets (file servers, web servers, CMS, etc.)
- Includes tool outputs (nikto, nuclei) for baseline creation
- Well-organized and documented
- Recent scans with current service versions

### 2. zephinzer/comat-ceh-report
- **Source:** https://github.com/zephinzer/comat-ceh-report
- **Content:** 1 Nessus scan (39 vulnerabilities)
- **Quality:**  Fair
- **Verdict:** Not selected - No nmap scans, only Nessus output

**Why Not Selected:**
- Missing nmap scan data (only has Nessus reports)
- Only 1 host scanned
- Would require synthetic nmap data creation

### 3. DRT709/Metasploitable-ub1404-PenTest
- **Source:** https://github.com/DRT709/Metasploitable-ub1404-PenTest
- **Content:** PDF reports only
- **Quality:**  Poor
- **Verdict:** Not selected - No machine-readable data

**Why Not Selected:**
- No nmap XML files found
- Only PDF reports (not machine-readable)
- Cannot automate parsing

### 4. rahulkore1/basic-vulnerability-assessment
- **Source:** https://github.com/rahulkore1/-basic-vulnerability-assessment
- **Content:** PDFs and screenshots
- **Quality:**  Poor
- **Verdict:** Not selected - No usable scan data

**Why Not Selected:**
- Only PDF reports and screenshots
- No machine-readable nmap data
- Poor repository organization

---

## Target Selection from InfoSecWarrior

From the 11 available targets, we analyzed and scored each based on:
- Number of open ports
- Service diversity
- Known vulnerable services
- Availability of tool outputs
- Version information for CVE mapping

### Scoring Results (Top 5)

| Rank | Target | Score | Ports | Vulnerable Services | Tool Outputs |
|------|--------|-------|-------|---------------------|--------------|
| 1 | My-File-Server-1 | 136 | 8 | FTP, NFS, SMB, RPC | nikto, nuclei, dirsearch |
| 2 | My-File-Server-2 | 136 | 8 | FTP, NFS, SMB, RPC | nikto, nuclei, dirsearch |
| 3 | My-Web-Server | 70 | 7 | MySQL, AJP13 | nikto, nuclei, dirsearch |
| 4 | It's-October | 56 | 4 | MySQL, HTTP | nikto, nuclei, dirsearch |
| 5 | My-CMS-MS | 45 | 4 | MySQL, HTTP | nikto, nuclei, dirsearch |

### Final Selection

**For Midterm Demonstration:**
- **Primary:** My-File-Server-1 (192.168.1.39)
  - 8 open ports with 6 vulnerable services
  - Already tested and validated
  - Comprehensive baseline created

**For Future Work:**
- All top 5 targets available for AI/ML training
- Diverse vulnerability types across targets
- 13 unique services for comprehensive testing

---

## Validation Results

**My-File-Server-1 Test Results:**
- **Scan Date:** September 29, 2024
- **Vulnerabilities Detected:** 5 (3 critical, 1 high, 1 medium)
- **Evaluation Metrics:**
  - Precision: 40%
  - Recall: 40%
  - F1 Score: 0.400
- **Real Vulnerabilities Found:**
  - FTP anonymous login (vsftpd 3.0.2)
  - NFS exposed (port 2049)
  - SMB service (port 445)
  - HTTP unencrypted (Apache 2.4.6)

---

## Files Generated During Testing

### Test Scripts
- `scripts/download_public_datasets.py` - Downloads all 4 datasets
- `scripts/comprehensive_dataset_test.py` - Tests dataset quality
- `scripts/select_best_targets.py` - Analyzes and ranks targets
- `scripts/parse_nessus_baseline.py` - Parses Nessus for comparison

### Test Results
- `datasets/analysis_results.json` - Initial dataset analysis
- `datasets/comprehensive_test_results.json` - Detailed test results
- `datasets/target_selection.json` - Target ranking and selection

### Documentation
- `DATASET_COMPARISON.md` - Full comparison of all 4 datasets
- `REAL_DATASET_OPTIONS.md` - Options for obtaining real data
- `DATASET_GUIDE.md` - Guide for dataset acquisition

---

## Academic Citation

For our project report, we cite:

> "We evaluated four publicly available vulnerability scan datasets and selected 
> the InfoSecWarrior/Vulnerable-Box-Resources dataset (GitHub: 
> https://github.com/InfoSecWarrior/Vulnerable-Box-Resources) based on completeness, 
> data quality, and suitability for validation. This dataset contains 822 nmap scans 
> across 11 vulnerable systems, scanned in September 2024. We selected My-File-Server-1 
> as our primary validation target, which contains 8 open ports with 6 known vulnerable 
> services including FTP, NFS, and SMB."

---

## Lessons Learned

1. **Dataset quality varies widely** - Many public datasets lack machine-readable data
2. **Tool outputs are valuable** - Having nikto/nuclei outputs helps create baselines
3. **Diversity matters** - Multiple targets with different services improves validation
4. **Recent scans preferred** - September 2024 scans have current vulnerability landscape
5. **Documentation is key** - Well-organized repositories are easier to work with

---

## Recommendation for Future Students

If you need a vulnerability scan dataset:

1. **Start with InfoSecWarrior/Vulnerable-Box-Resources** - Best public option
2. **Avoid PDF-only datasets** - Not machine-readable
3. **Check for nmap XML** - Essential for automated parsing
4. **Look for tool outputs** - Helps create ground truth baselines
5. **Verify scan dates** - Recent scans have current vulnerability data

---

## Summary

**Final Dataset:** InfoSecWarrior/Vulnerable-Box-Resources  
**Primary Target:** My-File-Server-1  
**Backup Targets:** 4 additional targets available  
**Quality:** Excellent - Real, recent, complete data  
**Status:**  Validated and ready for use

This dataset provides a solid foundation for our midterm demonstration and future 
AI/ML enhancements.
