import csv
from snykApi.snykApi import *
from helpers.helper import *
from datetime import date

def return_snyk_orgs_based_on_policy(args):
    if ',' not in args:
        orgs = get_orgs(args)
        results = get_issues_reporting(orgs)
        create_csv(results[0])
    else:
        groupIds = separate_guids(args)
        for groupId in groupIds:
            print(f"Returning organizations for {groupId}")
            orgs = get_orgs(groupId)
            results = get_issues_reporting(orgs)
            create_csv(results[0], groupId)

def create_csv(*args):
    todaysDate = date.today()
    
    if len(args) == 2:
        csvName = f'snyk_orgs_data_{todaysDate}_{args[1]}.csv'
    else:
        print(args[0])
        csvName = f'snyk_orgs_data_{todaysDate}.csv'
    try:
        with open(csvName, 'w', newline='') as file:
            writer = csv.writer(file)
            fields = ["Organziation name", "Organization ID"]

            writer.writerow(fields)
            for orgData in args[0]:
                writer.writerow([f"{orgData['name']}", f"{orgData['id']}"])
    except IOError as err:
        print(f"Failed to create csv.  Please see error here: {err}")