import json
import requests
import time

from helpers.helper import get_snyk_token

SNYK_TOKEN = get_snyk_token()

restHeaders = {'Content-Type': 'application/vnd.api+json', 'Authorization': f'token {SNYK_TOKEN}'}
v1Headers = {'Content-Type': 'application/json; charset=utf-8', 'Authorization': f'token {SNYK_TOKEN}'}

def get_orgs(groupId):
    print("Collecting organization IDs")
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
    print("Searching for orgs that match policy")
    count = 0

    for orgData in orgsData:
        url = 'https://api.snyk.io/v1/reporting/issues/latest'
        orgId = orgData['id']
        orgName = orgData['attributes']['name']
        time.sleep(0.5)
        try:
            count += 1
            body = {"filters":{"orgs":[orgId],"severity":["critical","high"],"exploitMaturity":["mature","proof-of-concept"],"types":["vuln"],"languages":["node","javascript","ruby","java","scala","python","golang","php","dotnet","swift-objective-c","elixir","docker","linux","dockerfile","terraform","kubernetes","helm","cloudformation","arm"],"ignored":False,"fixable":True,"isUpgradable":True}}
            issuesReportingApiResponse = requests.post(url, headers=v1Headers, data=json.dumps(body))
            issueData = issuesReportingApiResponse.json()['results']
            if len(issueData) == 0:
                orgNameAndId = {'name': orgName, 'id': orgId}
                passPolicyList.append(orgNameAndId)
            else:
                orgNameAndId = {'name': orgName, 'id': orgId}
                failedPolicyList.append(orgNameAndId)
            
            print(f'Processing organization {count} of {len(orgsData)}')

        except:
            print("Issue endpoint call failed.")
            print(issuesReportingApiResponse.json())
    
    return passPolicyList, failedPolicyList