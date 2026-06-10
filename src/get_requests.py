#########################
# This script requires to have previously run the init_azure.py, the get_all_permissions.py, and the get_all_roles.py script
# This script generates a suggestion for permission requests based on the permission descriptions present in the built-in roles.
# Therefore, you need to set your CHOSEN_CATEGORIES.
# For each chosen category, the script generates files in the subdirectory requests_proposal
# As mentioned after finishing the script, please check that:
# A) The requests show no grammatical errors in requests_proposal.
# -> Track the IDs you want to discard and run finalize_requests.py
#########################

import csv
from pathlib import Path
import os
import shutil
import sys
import re
import json
from collections import Counter

# script is located at <project>/src/get_all_permissions.py -> get <project>
PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Based on 2026-04-28:
##### Assignable scopes unequal to ''/''.
# >>management-and-governance.md<<
# - reservations reader
# - service group administrator
# - service group contributor
# - service group reader
# >>privileged.md<<
# - reservations administrator
#
# -> Choose other categories!

# Choose categories
CHOSEN_CATEGORIES = ["devops", "ai-machine-learning", "containers"]

# Path to built-in-roles in azure
BUILT_IN_ROLES_DIRECTORY = os.path.join(PROJECT_ROOT, "azure_rbac", "articles", "role-based-access-control", "built-in-roles")

# Path to roles_data.csv
ROLES_DATA_FILE = os.path.join(PROJECT_ROOT, "data", "all_roles", "roles_data.csv")

# Path to all_roles -> preprocessed_pa directory
ALL_ROLES_PREPROCESSED_DIRECTORY = os.path.join(PROJECT_ROOT, "data", "all_roles", "preprocessed_pa")

# Path to directory that stores the request subdirectories
REQUESTS_DIRECTORY = os.path.join(PROJECT_ROOT, "data", "requests")

# Path to request subdirs
REQUESTS_PROPOSAL_DIRECTORY = os.path.join(REQUESTS_DIRECTORY, "requests_proposal")
REQUESTS_FINAL_DIRECTORY = os.path.join(REQUESTS_DIRECTORY, "requests_final")

# Go through categories' md file line by line and return a list of role names and associated, granted permissions
def parse_md_file(category):
    # Path to built-in roles md file of category
    category_md_path = os.path.join(BUILT_IN_ROLES_DIRECTORY, category + ".md")
    # Names and number of roles in this category according to preprocessed pa file (no denied operations)
    valid_roles = set()
    number_valid_roles = 0
    preprocessed_file = os.path.join(ALL_ROLES_PREPROCESSED_DIRECTORY, f"{category}.csv")
    # Open file and read file
    with open(preprocessed_file, "r", newline="", encoding="utf-8") as preprocessed_csv:
        reader = csv.DictReader(preprocessed_csv)
        for row in reader:
            if row["role_name"] not in valid_roles:
                valid_roles.add(row["role_name"])
                number_valid_roles += 1

    # Next, we parse the md file
    with open(category_md_path, encoding="utf-8") as f:
        lines = f.readlines()
        roles = []
        counter_found_roles = 0
        current_role = None
        i = 0

        # Traversing all lines of document
        while i < len(lines):
            # Get current line
            line = lines[i].strip()

            # Does the current line start with ## ? -> It might be a role name!
            # After setting the current_role, we "Move to the next line" until reaching new mx-tableFixed block
            if line.startswith("## "):
                current_role_candidate = line.replace("## ", "").strip().lower()
                # If reaching next steps -> Break out of traversing document
                if current_role_candidate == "next steps":
                    print(
                        "Found ''## Next steps'' for category " + category + ". Breaking out of traversing the md document.")
                    break
                # Check if role name corresponds to a role name in preprocessed pa file
                if current_role_candidate in valid_roles:
                    current_role = current_role_candidate
                    counter_found_roles += 1
                else:
                    current_role = "INVALID"

            # Reached new mx-tableFixed block (which belongs to the last found current_role)
            if "> [!div class=\"mx-tableFixed\"]" in line:
                # Found a role table block
                # Data type to store the role's permission names and requests
                role_permission_data = {
                    "role_name": current_role,
                    "permissions": []
                }
                # role_name and list of granted (permission, descr) tuples:
                # {'role_name': 'load test reader', 'permissions': [('[microsoft.loadtestservice](../permissions/devops.md#microsoftloadtestservice)/*/read', 'read load testing resources'), ('p','d'), ...]}

                # Move forward to the next line
                i += 1
                # Now, check that this line is "> | Actions | Description |"
                if "> | Actions | Description |" != lines[i].strip():
                    print("Should have found ''> | Actions | Description |'' after the ''mx-tableFixed'' table header.")
                    print("Error in role " + current_role + " of category: " + category)
                    exit(1)

                # Move forward to the next line
                i += 1
                # Now, check that this line is "> | --- | --- |"
                if "> | --- | --- |" != lines[i].strip():
                    print(
                        "Should have found ''> | --- | --- |'' after the ''> | Actions | Description |'' line.")
                    print("Error in role " + current_role + " of category: " + category)
                    exit(1)

                # Move forward to the next line -> The first action.
                i += 1
                # Store data and move until reaching "> | **NotActions** |  |"
                while not lines[i].strip() == "> | **NotActions** |  |":
                    row = lines[i].strip()[2:].strip()  # Remove leading "> "
                    cols = [col.strip() for col in row.split("|")[1:-1]]  # Create columns based on "|" separator
                    permission = cols[0].strip().lower()
                    description = cols[1].strip().lower()
                    if permission != "*none*":
                        role_permission_data["permissions"].append((permission, description))
                    # Move to the next line
                    i += 1

                # Now, the line starts with "> | **NotActions** |  |", skip this line
                i += 1
                # Do not store data and move until reaching "> | **DataActions** |  |"
                while not lines[i].strip() == "> | **DataActions** |  |":
                    # Move to the next line
                    i += 1

                # Now, the line starts with "> | **DataActions** |  |", skip this line
                i += 1
                # Store data and move until reaching "> | **NotDataActions** |  |"
                while not lines[i].strip() == "> | **NotDataActions** |  |":
                    row = lines[i].strip()[2:].strip()  # Remove leading "> "
                    cols = [col.strip() for col in row.split("|")[1:-1]]  # Create columns based on "|" separator
                    permission = cols[0].strip().lower()
                    description = cols[1].strip().lower()
                    if permission != "*none*":
                        role_permission_data["permissions"].append((permission, description))
                    # Move to the next line
                    i += 1

                # Now, the line starts with "> | **NotDataActions** |  |", skip this line
                i += 1
                # Do not store data and move until reaching "" or "> | **Actions** |  |"
                while (
                        lines[i].strip() != "> | **Actions** |  |"
                        and lines[i].strip() != ""
                ):
                    # Move to the next line
                    i += 1

                # Now, the line either starts with "> | **Actions** |  |" (second permissions entry) or "" (finished block)
                # Only continue traversing for this role, if lines[i] == "> | **Actions** |  |"
                if lines[i].strip() == "> | **Actions** |  |":
                    # Now, the line starts with "> | **Actions** |  |", skip this line
                    i += 1
                    # Store data and move until reaching "> | **NotActions** |  |"
                    while not lines[i].strip() == "> | **NotActions** |  |":
                        row = lines[i].strip()[2:].strip()  # Remove leading "> "
                        cols = [col.strip() for col in row.split("|")[1:-1]]  # Create columns based on "|" separator
                        permission = cols[0].strip().lower()
                        description = cols[1].strip().lower()
                        if permission != "*none*":
                            role_permission_data["permissions"].append((permission, description))
                        # Move to the next line
                        i += 1

                    # Now, the line starts with "> | **NotActions** |  |", skip this line
                    i += 1
                    # Do not store data and move until reaching "> | **DataActions** |  |"
                    while not lines[i].strip() == "> | **DataActions** |  |":
                        # Move to the next line
                        i += 1

                    # Now, the line starts with "> | **DataActions** |  |", skip this line
                    i += 1
                    # Store data and move until reaching "> | **NotDataActions** |  |"
                    while not lines[i].strip() == "> | **NotDataActions** |  |":
                        row = lines[i].strip()[2:].strip()  # Remove leading "> "
                        cols = [col.strip() for col in row.split("|")[1:-1]]  # Create columns based on "|" separator
                        permission = cols[0].strip().lower()
                        description = cols[1].strip().lower()
                        if permission != "*none*":
                            role_permission_data["permissions"].append((permission, description))
                        # Move to the next line
                        i += 1

                    # Now, the line starts with "> | **NotDataActions** |  |", skip this line
                    i += 1
                    # Do not store data and move until reaching """"
                    while lines[i].strip() != "":
                        # Move to the next line
                        i += 1

                # You reached the empty line before the json block starting with ```json
                # Thus, add your role_permission_data to roles if the role was valid
                if current_role != "INVALID":
                    roles.append(role_permission_data)
                # List of role_name and assigned (permission, descr) tuples
                # [{'role_name': 'roleA', 'permissions': [('permission', 'description'), ('permission2', 'description2'), ..., ]}, {'role_name': 'roleB', 'permissions': [('permission3', 'description3'), ...

            # Move to the next line until finding "## " -> new role candidate or "> [!div class=\"mx-tableFixed\"]"
            i += 1

    # Check if number of roles corresponds to csv file creating when running get_roles.py -> Else: Error + Exit
    # "Found all roles"
    if number_valid_roles != counter_found_roles:
        print("In category " + category + ", the number of found roles does not correspond to the number of roles in /all_roles/preprocessed_pa/")
        exit(1)

    return roles

# Create a list of role-permission tuples with permission names as found in the json role entries
# Returned via json_roles
def get_list_of_json_roles(category, roles):
    # Find all json blocks in md file
    category_md_path = os.path.join(BUILT_IN_ROLES_DIRECTORY, category + ".md")
    with open(category_md_path, encoding="utf-8") as category_md_file:
        content = category_md_file.read()
    # PATTERN
    # Start: ```json
    # any character (.), zero or more times (*), stop at first ```
    # End: ```
    # DOTALL -> Capture newline characters
    # IGNORECASE -> json, JSON, Json, etc...
    json_blocks = re.findall(r"```json(.*?)```", content, re.DOTALL | re.IGNORECASE)

    # List of role-permission tuples with permission names of granted permissions (!) as found in the JSON blocks
    json_roles = []
    # [(r, p), (r2, p2), ...
    # [('chaos studio experiment contributor', 'microsoft.chaos/*'), ('chaos studio experiment contributor', 'microsoft.authorization/*/read'), ...

    # For each json role found in current md file...
    # Store permission names in same order as previously found in the mx-tableFixed blocks -> INTO json_roles
    # Compared to the all_roles/preprocessed_pa/{category}.csv files, this list must not be unique
    for block in json_blocks:
        try:
            # Load the data, incl. role description, roleName, permissions, etc.
            data = json.loads(block)
            # get permissions of role
            permissions = data.get("permissions", "")
            valid_role = True
            # 1 - 2 iterations
            for perms in permissions:
                # Store all permissions of type notActions or notDataActions
                not_actions_data_actions = (
                        perms.get("notActions", [])
                        + perms.get("notDataActions", [])
                )
                if len(not_actions_data_actions) > 0:
                    valid_role = False
            if valid_role:
                # 1 - 2 iterations
                for perms in permissions:
                    # Store all permissions of type actions or dataActions
                    actions_data_actions = (
                            perms.get("actions", [])
                            + perms.get("dataActions", [])
                    )
                    # Add permissions to json_roles and allowed_targets
                    for action in actions_data_actions:
                        json_roles.append((data.get("roleName", "").strip().lower(), action.strip().lower()))
        except json.JSONDecodeError:
            print("Found invalid JSON block in category: " + category)
            exit(1)

    # Validation Check -> Each role has the same number of "positive" permission entries in JSON blocks and table blocks
    # Number of permissions per json role block
    json_role_counts = Counter(role for role, _ in json_roles)

    for role in roles:
        role_name = role["role_name"]
        # Number of permissions of role table structure
        permission_count = len(role["permissions"])
        # Compare counts
        json_count = json_role_counts.get(role_name, 0)
        if permission_count != json_count:
            print(
                "In category " + category + ", the role " + role_name + " has a different number of allowed permissions when comparing json blocks and [!div class=""mx-tableFixed""] blocks.")
            exit(1)

    return json_roles

# Transform the descr. of a permission to a request
def transform_description_to_request(description):
    request = description
    if request != "":
        request = request.strip()
        # If request ends with " ." -> remove this
        request = request[:-2] if request.endswith(' .') else request

        # Remove not alertable
        if request.endswith("not alertable."):
            request = request[:-14]
            request = request.strip()
        elif request.endswith("not alertable"):
            request = request[:-13]
            request = request.strip()

        # Ensure sentence ends with a period
        request = request if request.endswith('.') else request + '.'

        # Prefix
        request = "I need to " + request

        # If forth word is in 3rd personal singular -> Remove "s"
        # -> "I need to create" instead of "I need to creates"
        removed_s = False
        words = request.split()
        if words[3].endswith('s'):
            words[3] = words[3][:-1]  # remove last character (s)
            removed_s = True
            # I need to updates/add something -> I need to update/add something
            if 's/' in words[3]:
                words[3] = words[3].replace('s/', '/')

        # If forth word was in 3rd personal singular, there might be a second word in 3rd personal singular
        # Description: gets or lists a table
        # So far -> I need to get or lists a table
        # Correct -> I need to get or list a table
        if removed_s:
            # Traverse all words
            for i in range(1, len(words)):
                if words[i - 1] in ("and", "or") and words[i].endswith('s'):
                    words[i] = words[i][:-1]

        request = " ".join(words)
    else:
        request = "NULL"

    return request

def main():
    # Check if directory exists. If not -> error and exit
    if not os.path.isdir(BUILT_IN_ROLES_DIRECTORY):
        print("The " + BUILT_IN_ROLES_DIRECTORY + " directory is missing.")
        print("Did you run init_azure.py?")
        exit(1)

    # Check if file exists. If not -> error and exit
    if not os.path.isfile(ROLES_DATA_FILE):
        print("The " + ROLES_DATA_FILE + " file was not found.")
        print("Did you run get_all_roles.py?")
        exit(1)

    # Check if directory exists. If not -> error and exit
    if not os.path.isdir(ALL_ROLES_PREPROCESSED_DIRECTORY):
        print("The " + ALL_ROLES_PREPROCESSED_DIRECTORY + " directory is missing.")
        print("Did you run get_all_roles.py?")
        exit(1)

    # Store all categories from azure built-in roles
    all_categories = []
    for entry in os.listdir(BUILT_IN_ROLES_DIRECTORY):
        name, ext = os.path.splitext(entry)  # extract name of md file, e.g. "Storage"
        all_categories.append(name)

    all_categories = [item.strip().lower() for item in all_categories] # -> "storage"

    # Are chosen categories OK?
    chosen_categories_lowercased = [item.strip().lower() for item in CHOSEN_CATEGORIES]
    for category in chosen_categories_lowercased:
        if category not in all_categories:
            print("The chosen category " + category + " was not recognized as an Azure category.")
            exit(1)

    # Continue or abort
    print("The following categories were chosen inside the code:")
    for category in chosen_categories_lowercased:
        print(category)

    answer = input("Continue? [y/N]").strip().lower()
    if answer != "y":
        print("Aborted.")
        sys.exit(0)

    print("Continuing using the listed categories...")

    # If directory does not exist -> Create. If it does exist -> Empty
    if not os.path.isdir(REQUESTS_DIRECTORY):
        # Command makedirs would also create data directory if missing
        # -> data directory should always exist, because init_azure was run before
        os.makedirs(REQUESTS_DIRECTORY, exist_ok=True)
    else:
        # If existing -> empty requests_directory directory
        for entry in os.listdir(REQUESTS_DIRECTORY):
            path = os.path.join(REQUESTS_DIRECTORY, entry)

            if os.path.isfile(path) or os.path.islink(path):
                os.unlink(path)
            elif os.path.isdir(path):
                shutil.rmtree(path)

    # Create subdirs
    os.makedirs(REQUESTS_PROPOSAL_DIRECTORY)
    os.makedirs(REQUESTS_FINAL_DIRECTORY)

    # Required later when writing rows into the files within the requests_proposal subdirectory
    id = 0

    # For each chosen category
    for category in chosen_categories_lowercased:
        # List of role_name and assigned (permission, descr) tuples
        # [{'role_name': 'roleA', 'permissions': [('permission', 'description'), ('permission2', 'description2'), ..., ]}, {'role_name': 'roleB', 'permissions': [('permission3', 'description3'), ...
        roles = parse_md_file(category)
        # [('chaos studio experiment contributor', 'microsoft.chaos/*'), ('chaos studio experiment contributor', 'microsoft.authorization/*/read'), ...
        json_roles = get_list_of_json_roles(category, roles)

        # Combine roles and json_roles into single set
        # We store the name of each permission 2 times
        # -> One time the permission name from role in roles, one time from the json_roles
        # This is because we have the description in roles, but the correct permission name in json_roles
        # Check manually, that there is no mistake after running this script
        descr = set()
        x = -1 # json_roles tuple id
        for role in roles:
            for permission_name, permission_description in role["permissions"]:
                x += 1
                json_permission_name = json_roles[x][1]
                if permission_description != "":
                    descr.add((json_permission_name, permission_name, permission_description))

        # Transform descriptions into requests and check that permission_name and json_permission name are the same
        requ_raw = set()
        for json_permission_name, permission_name, permission_description in descr:
            requ_raw.add((
                json_permission_name, permission_name, transform_description_to_request(permission_description)
            ))
            # Remove [
            check_permission_name = permission_name[1:]
            # Remove everything between ]( and )
            start = check_permission_name.find('](')
            end = check_permission_name.find(')', start)

            check_permission_name = check_permission_name[:start] + check_permission_name[end+1:]

            if check_permission_name != json_permission_name:
                print("There was a permission name from the parsed md files that does not correspond to the json permission in the same line.")
                print(permission_name)
                print(json_permission_name)
                exit(1)

        # Count request occurrences
        request_counts = Counter(row[2] for row in requ_raw)

        # Do not allow requests which occurred more than 1 time.
        requ_no_null = {row for row in requ_raw if request_counts[row[2]] == 1}
        requ_no_null_sorted = sorted(requ_no_null)

        # Create {category}.csv file in requests_proposal directory to store:
        # permission_name, json_permission_name, request
        requests_proposal_file = os.path.join(REQUESTS_PROPOSAL_DIRECTORY, category + ".csv")

        # Open file and write contents into the requests proposal file
        with open(requests_proposal_file, "w", newline="", encoding="utf-8") as requests_proposal_csv:
            writer = csv.writer(requests_proposal_csv)
            # Write header
            writer.writerow(
                ["id", "json_permission_name", "permission_name", "request"]
            )

            # Write rows with incrementing ID
            for row in requ_no_null_sorted:
                writer.writerow([id, *row])  # prepend ID
                id += 1

    print("Finished creating request suggestions.")
    print("For each file created in " + REQUESTS_PROPOSAL_DIRECTORY + ", please check if:")
    print("A) There are no grammatical errors in the requests.")
    print("Please keep track of the request IDs which you want to discard.")
    print("As a next step, we recommend to run finalize_requests.py")

if __name__ == "__main__":
    main()