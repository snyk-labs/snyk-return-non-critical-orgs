import json
import time
import requests
import os

from helpers.helper import check_if_issues_exist

SNYK_TOKEN = os.getenv('SNYK_TOKEN')
GROUP_ID = os.getenv('GROUP_ID')
restHeaders = {'Content-Type': 'application/vnd.api+json', 'Authorization': f'token {SNYK_TOKEN}'}
v1Headers = {'Content-Type': 'application/json; charset=utf-8', 'Authorization': f'token {SNYK_TOKEN}'}

def get_orgs(groupId):
    print("Collecting org ids")
    url = f'https://api.snyk.io/rest/groups/{groupId}/orgs?version=2024-05-08&limit=100'
    hasNextLink = True
    orgs = []

    while hasNextLink:
        try:
            orgApiResponse = requests.get(url, headers=restHeaders)
            orgData = orgApiResponse.json()['data']
            orgs.extend(orgData)
        except:
            print("Orgs endpoint call failed.")
            print(orgApiResponse)
        
        # Check if next page exist and set url if it does.  If not, exit and return issuesData
        try:
            orgApiResponse.json()['links']['next']
            url = 'https://api.snyk.io' + orgApiResponse.json()['links']['next']
        except:
            hasNextLink = False
            return orgs

def get_issues_reporting(orgsData):
    failedPolicyList = []
    passPolicyList = []
    missedOrgs = []

    print("Searching for orgs that match policy")
    count = 0

    for orgData in orgsData:
        url = 'https://api.snyk.io/v1/reporting/issues/latest'
        orgId = orgData['id']
        time.sleep(0.5)
        try:
            count += 1
            body = {"filters":{"orgs":[orgId],"severity":["critical","high"],"exploitMaturity":["mature","proof-of-concept"],"types":["vuln"],"languages":["node","javascript","ruby","java","scala","python","golang","php","dotnet","swift-objective-c","elixir","docker","linux","dockerfile","terraform","kubernetes","helm","cloudformation","arm"],"ignored":False,"fixable":True,"isUpgradable":True}}
            issuesReportingApiResponse = requests.post(url, headers=v1Headers, data=json.dumps(body))
            issueData = issuesReportingApiResponse.json()['results']

            issueExist = check_if_issues_exist(issueData, orgId)
            if issueExist[1]:
                passPolicyList.append(issueExist[0])
            else:
                failedPolicyList.append(issueExist[1])
            
            print(f'Processing organization {count} of {len(orgsData)}')

        except:
            missedOrgs.append(orgId)
            print("Issue endpoint call failed.")
            print(issuesReportingApiResponse.json())
    
    return passPolicyList, failedPolicyList

orgs = get_orgs(GROUP_ID)
results = get_issues_reporting(orgs)

print (f'list of eligible orgs: {results[0]}')

