import os
import re
import sys

def check_if_issues_exist(issueData, orgData):
    if len(issueData) == 0:
        return orgData['id'], True
    else:
        return orgData['id'], False
        
def separate_guids(guid_list):
    try:
        org_ids = guid_list.split(",")
        if validate_guid_ids(org_ids):
            return org_ids
        else:
            return False
    except:
        if validate_guid_ids(org_ids):
            return org_ids
        else:
            return False

def validate_guid_ids(guid_list):
    pattern = re.compile(r'([\d\w]{8}-[\d\w]{4}-[\d\w]{4}-[\d\w]{4}-[\d\w]{12})')
    for guid in guid_list:
        if pattern.fullmatch(guid) == None:
            return False
    
    return True

def get_snyk_token():
    SNYK_TOKEN = check_if_snyk_token_exist()
    
    pattern = re.compile(r'([\d\w]{8}-[\d\w]{4}-[\d\w]{4}-[\d\w]{4}-[\d\w]{12})')
    if pattern.fullmatch(SNYK_TOKEN) == None:
        print("Snyk token is not defined or not valid.")
        sys.exit()
    else:
        return SNYK_TOKEN

def check_if_snyk_token_exist():
    print("Checking for Snyk token environment variable")
    try:
        if os.environ.get('SNYK_TOKEN'):
            print("Found snyk token")
            return os.getenv('SNYK_TOKEN')
    except:
        print("Snyk token does not exist")
        sys.exit()