# Return Snyk organizations that do not have any critical and high issues with exploits and fixes

This script will find all organziations that do not have high and critical issues but this can be modified in the get_issues_reporting methond in snykApi.py. 

## Requirements

Python version 3.9.5

## Running
```bash
export SNYK_TOKEN=TYPE-TOKEN-SNYK-HERE
git clone https://github.com/snyk-labs/snyk_return_non_critical_orgs.git
pip install -r requirements.txt
python3 index.py 12345678-1234-1234-1234-123456789012
```
