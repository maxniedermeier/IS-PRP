#########################
# This script requires to have previously run the init_azure.py and the get_all_permissions.py script
# It creates two files in <project>/data/all_roles:
# roles_data.csv lists, for all categories -> all role names, role ids, assignable scopes, and the information
# whether the role contains "denied" operations
# get_all_roles_information.txt stores the output information of this script
# It creates several files in <project>/data/all_roles/preprocessed_pa
# Each <category>.csv is a csv file for storing the role-to-permission assignments of an azure category
# A category can be for example ai-machine-learning, analytics, compute, ..., web-and-mobile
# However, we only include roles that do not contain any "denied" operations
# COLUMNS: role_name and permission_name (wildcard and explicit permission names as found in the built-in-roles)
#########################

from pathlib import Path
import os
import shutil
import re
import json
import csv
from collections import defaultdict

# script is located at <project>/src/get_all_roles.py -> get <project>
PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Path to built-in-roles in azure
BUILT_IN_ROLES_DIRECTORY = os.path.join(PROJECT_ROOT, "azure_rbac", "articles", "role-based-access-control", "built-in-roles")

# Path to directory that stores a list of (1) all roles data, (2) information generated when running this script,
# and (3) the preprocessed subdirs mentioned in the script description
ALL_ROLES_DIRECTORY = os.path.join(PROJECT_ROOT, "data", "all_roles")

# Preprocessed subdir where csv files are stored
ALL_ROLES_PREPROCESSED_DIRECTORY = os.path.join(ALL_ROLES_DIRECTORY, "preprocessed_pa")

# Path to log file that stores the terminal information
GET_ALL_ROLES_INFORMATION_FILE = os.path.join(ALL_ROLES_DIRECTORY, "get_all_roles_information.txt")

# Path to roles_data.csv file
ROLES_DATA_FILE = os.path.join(ALL_ROLES_DIRECTORY, "roles_data.csv")

# Traverse built-in roles markdown files and return information about all roles
def create_roles_overview(log_writer):
    # List of role information (5-tuple): category, role name, role id, assignable scopes, denied operations?
    roles_data = []

    # For each markdown category file, find json blocks (roles)
    for category in os.listdir(BUILT_IN_ROLES_DIRECTORY):
        # Path to markdown category file
        path = os.path.join(BUILT_IN_ROLES_DIRECTORY, category)
        with open(path, "r", encoding="utf-8") as md_file:
            content = md_file.read()
        # Find all json files
        # PATTERN
        # Start: ```json
        # any character (.), zero or more times (*), stop at first ```
        # End: ```
        # DOTALL -> Capture newline characters
        # IGNORECASE -> json, JSON, Json, etc...
        json_blocks = re.findall(r"```json(.*?)```", content, re.DOTALL | re.IGNORECASE)

        # For each role found...
        for block in json_blocks:
            try:
                # Load the data, incl. role description, roleName, permissions, etc.
                data = json.loads(block)
                # 1) Get role name of role
                role_name = data.get("roleName", "")
                role_name = role_name.strip().lower()
                # 2) Get ID of role
                role_id = data.get("name", "")  # id is called name in azure
                role_id = role_id.strip().lower()
                # 3) Get assignable scopes
                assignable_scopes = data.get("assignableScopes", "")
                # Should always have len == 1
                if len(assignable_scopes) != 1:
                    print("Found assignable scopes of a role with size unequal to 1.")
                    print("Category: " + category)
                    print("Role name: " + data.get("roleName", []))
                    exit(1)

                assignable_scopes = assignable_scopes[0].strip().lower()
                # Create an information for outliers having assignable_scopes != "/"
                if assignable_scopes != "/":
                    msg = "Info: Role >>" + role_name + "<< in >>" + category + "<< has assignable scopes unequal to ''/''."
                    print(msg)
                    log_writer.write(msg + "\n")
                    msg = "-> Assignable Scopes: " + assignable_scopes
                    print(msg + "\n")
                    log_writer.write(msg + "\n\n")

                # 4) Check if role denies operations
                contains_deny_operations = False
                permissions = data.get("permissions", [])
                contains_deny_operations = any(
                    perms.get("notActions") or perms.get("notDataActions")
                    for perms in permissions
                )

                # Add azure category, role name, role id, assignable scopes
                roles_data.append((category, role_name, role_id, assignable_scopes, contains_deny_operations))
            except json.JSONDecodeError:
                print("Found invalid JSON block in category: " + category)
                exit(1)

    return roles_data

# For each markdown file of built-in-roles, create a csv files showing which role contains what permission.
# Do not include roles which contain denied operations
def create_role_permission_assignments(log_writer):
    # Traverse category files
    for category in os.listdir(BUILT_IN_ROLES_DIRECTORY):
        # Path to new csv file
        name, ext = os.path.splitext(category)  # extract name of md file
        preprocessed_file = os.path.join(ALL_ROLES_PREPROCESSED_DIRECTORY, f"{name}.csv")
        # Set of role-to-permission assignments for the current markdown file, including wildcard permissions
        # role_name, permission_name
        pa: set[tuple[str, str]] = set()
        # Path to azure markdown file of category built-in role
        with open(os.path.join(BUILT_IN_ROLES_DIRECTORY, category), "r", encoding="utf-8") as md_file:
            content = md_file.read()
        # Find all json blocks in md file
        # PATTERN
        # Start: ```json
        # any character (.), zero or more times (*), stop at first ```
        # End: ```
        # DOTALL -> Capture newline characters
        # IGNORECASE -> json, JSON, Json, etc...
        json_blocks = re.findall(r"```json(.*?)```", content, re.DOTALL | re.IGNORECASE)

        # For each role found in current md file...
        for block in json_blocks:
            try:
                # Load the data, incl. role description, roleName, permissions, etc.
                data = json.loads(block)
                # get permissions of role
                permissions = data.get("permissions", "")
                # Permissions usually has len(permissions) = 1
                # However, in a few cases, len(permissions) = 2 as some roles have a second permission entry
                # which contains the ability to create and delete role assignments
                # Microsoft.Authorization/roleAssignments/write
                # Microsoft.Authorization/roleAssignments/delete
                if len(permissions) > 2:
                    print("Found a role with permissions size > 2.")
                    print("Built in roles: " + category)
                    print("Role name: " + data.get("roleName", ""))
                    exit(1)
                elif len(permissions) < 1:
                    print("Found a role with permissions size < 1.")
                    print("Built in roles: " + category)
                    print("Role name: " + data.get("roleName", ""))
                    exit(1)
                else:
                    # Open roles_data.csv ROLES_DATA_FILE
                    with open(ROLES_DATA_FILE, "r", newline='', encoding='utf-8') as roles_data_csv:
                        reader = csv.DictReader(roles_data_csv)
                        deny_operations = ""
                        # Check if the current role in this category denies operations
                        for row in reader:
                            if row['role_name'] == data.get("roleName", "").strip().lower():
                                deny_operations = row['deny_operations'].strip().lower()
                                break
                    # Only continue if no operations are denied in this role
                    if deny_operations == "false":
                        # 1 - 2 iterations
                        for perms in permissions:
                            # Store all permissions of type actions and dataActions
                            actions_data_actions = (
                                    perms.get("actions", [])
                                    + perms.get("dataActions", [])
                            )
                            # Add permissions to pa
                            for action in actions_data_actions:
                                pa.add((data.get("roleName", "").strip().lower(), action.strip().lower()))
                            # Get condition
                            condition = perms.get("condition", "")
                            # If condition is not empty, then write a message.
                            if condition != "":
                                msg = ("Info: Role >>" + data.get("roleName", "").strip().lower()
                                       + "<< in >>" + category + "<< has a condition in the 1st permission entry.")
                                print(msg)
                                log_writer.write(msg + "\n")
                                msg = "-> Condition: " + condition
                                print(msg + "\n")
                                log_writer.write(msg + "\n\n")
            except json.JSONDecodeError:
                print("Found invalid JSON block in category: " + category)
                exit(1)

        ordered_pa = sorted(pa)

        # Open file and write file
        with open(preprocessed_file, "w", newline="", encoding="utf-8") as preprocessed_csv:
            writer = csv.writer(preprocessed_csv)
            # Write header
            writer.writerow(["role_name", "permission_name"])
            # Write contents
            for role, permission in ordered_pa:
                writer.writerow([role, permission])

def main():
    # Check if azure built-in roles directory exists. If not -> error and exit
    if not os.path.isdir(BUILT_IN_ROLES_DIRECTORY):
        print("The " + BUILT_IN_ROLES_DIRECTORY + " directory is missing.")
        print("Did you run init_azure.py?")
        exit(1)

    # Check if all_roles dir exists. If not -> Create. If Yes -> Empty
    if not os.path.isdir(ALL_ROLES_DIRECTORY):
        # Command makedirs would also create data directory if missing
        # -> data directory should always exist, because init_azure was run before
        os.makedirs(ALL_ROLES_DIRECTORY, exist_ok=True)
    else:
        # If existing -> empty all_roles directory
        for entry in os.listdir(ALL_ROLES_DIRECTORY):
            path = os.path.join(ALL_ROLES_DIRECTORY, entry)

            if os.path.isfile(path) or os.path.islink(path):
                os.unlink(path)
            elif os.path.isdir(path):
                shutil.rmtree(path)

    # Create the subdirectory where the csv files for each category are stored
    os.makedirs(ALL_ROLES_PREPROCESSED_DIRECTORY, exist_ok=True)

    # Open log file
    log_writer = open(GET_ALL_ROLES_INFORMATION_FILE, "w")

    # As a first step, we create the roles_data.csv
    roles_data = create_roles_overview(log_writer)

    # Output:

    print("###########################################")
    print("")
    msg = "Info: Extracted a total of " + str(len(roles_data)) + " roles from traversing all built-in-roles markdown files."
    print(msg)
    print("")
    print("###########################################")
    print("")

    log_writer.write("###########################################"+"\n\n")
    log_writer.write(msg + "\n\n")
    log_writer.write("###########################################" + "\n\n")

    # Write roles_data.csv file
    with open(ROLES_DATA_FILE, "w", newline="", encoding="utf-8") as roles_data_csv:
        writer = csv.writer(roles_data_csv)
        # Write header
        writer.writerow(["category", "role_name", "role_id", "assignable_scopes", "deny_operations"])
        # Write contents
        for entry in roles_data:
            writer.writerow(entry)

    # Check if role names are unique across all markdown files
    unique_role_names = set()
    with open(ROLES_DATA_FILE, "r", newline='', encoding='utf-8') as roles_data_csv:
        reader = csv.DictReader(roles_data_csv)
        for row in reader:
            unique_role_names.add(row['role_name'])

    if len(roles_data) != len(unique_role_names):
        print("Number of found roles is not equal to number of all unique role names, across all Markdown files.")
        exit(1)

    # As a second step, create the category.csv files (role-to-permission assignments) of preprocessed roles
    create_role_permission_assignments(log_writer)

    # Write statistics
    print("###########################################")
    log_writer.write("###########################################" + "\n")
    msg = "Average number of permissions assigned and total number of permission targets"
    print(msg)
    log_writer.write(msg + "\n")
    msg = "Only considering roles without entries in notActions or notDataActions"
    print(msg)
    log_writer.write(msg + "\n")

    # Store results per category
    category_stats = {}

    # Traverse all role-to-permission csv files
    for root, dirs, preprocessed_category_files in os.walk(ALL_ROLES_PREPROCESSED_DIRECTORY):
        for category in preprocessed_category_files:
            prep_cat_file = os.path.join(root, category)
            # Per-role counters for this category
            file_roles = defaultdict(lambda: {'w': 0, 'e': 0})
            # Per category counter
            unique_permissions = set()
            # Open the file
            with open(prep_cat_file, mode='r', encoding='utf-8') as category_csv:
                reader = csv.DictReader(category_csv)
                # Traverse all rows
                for row in reader:
                    role_name = row['role_name']
                    permission_name = row['permission_name']
                    unique_permissions.add(permission_name)
                    if "*" in permission_name:
                        file_roles[role_name]['w'] += 1
                    else:
                        file_roles[role_name]['e'] += 1

            # Convert defaultdict to regular dict
            role_data = dict(file_roles)
            # Compute per-category averages
            total_roles = len(role_data)
            total_wildcard = sum(r['w'] for r in role_data.values())
            total_explicit = sum(r['e'] for r in role_data.values())
            avg_wildcard = total_wildcard / total_roles if total_roles > 0 else 0
            avg_explicit = total_explicit / total_roles if total_roles > 0 else 0

            category_stats[category] = {
                'per_role': role_data,
                'avg_wildcard': avg_wildcard,
                'avg_explicit': avg_explicit,
                'total_wildcard': total_wildcard,
                'total_explicit': total_explicit,
                'unique_permissions': len(unique_permissions)
            }

    for cat, stats in category_stats.items():
        num_roles = len(stats['per_role'])
        print(f"\nCategory: {cat}")
        print(f"Number of roles: {num_roles}")
        print(f"Number of UNIQUE permission targets: {stats['unique_permissions']}")
        print(f"Average wildcard permissions: {stats['avg_wildcard']:.2f}")
        print(f"Average explicit permissions: {stats['avg_explicit']:.2f}")

        log_writer.write(f"\nCategory: {cat}"+"\n")
        log_writer.write(f"Number of roles: {num_roles}"+"\n")
        log_writer.write(f"Number of UNIQUE permission targets: {stats['unique_permissions']}"+"\n")
        log_writer.write(f"Average wildcard permissions: {stats['avg_wildcard']:.2f}"+"\n")
        log_writer.write(f"Average explicit permissions: {stats['avg_explicit']:.2f}"+"\n")

    print("")
    log_writer.close()
    print("As a next step, we recommend to run get_requests.py")

if __name__ == "__main__":
    main()