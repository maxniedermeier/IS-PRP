#########################
# This script requires to have previously run the init_azure.py script
# It gathers all explicit permissions from the md files in
# <project>/azure_rbac/articles/role-based-access-control/permissions
# <project>/azure_rbac/articles/role-based-access-control/built-in-roles
# It gathers all wildcard permissions from the md files in
# <project>/azure_rbac/articles/role-based-access-control/built-in-roles
# It creates 5 files in <project>/data/all_permissions:
# all_explicit_permissions.txt is a list of all explicit permissions
# all_wildcard_permissions.txt is a list of all wildcard permissions
# wildcard_mapping.csv is a mapping showing which wildcard contains what explicit permissions
# wildcard_sizes.csv is a mapping showing the sizes of each wildcard permission
# get_all_permissions_information.txt stores the output information of this script
#########################

from pathlib import Path
import os
import shutil
import re
import json
from fnmatch import fnmatch
import csv
from collections import defaultdict

# script is located at <project>/src/get_all_permissions.py -> get <project>
PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Path to explicit permissions in azure
AZURE_PERMISSIONS_DIRECTORY = os.path.join(PROJECT_ROOT, "azure_rbac", "articles", "role-based-access-control", "permissions")

# Path to built-in-roles in azure
AZURE_BUILT_IN_ROLES_DIRECTORY = os.path.join(PROJECT_ROOT, "azure_rbac", "articles", "role-based-access-control", "built-in-roles")

# Path to directory that stores the generated contents by running this script
ALL_PERMISSIONS_DIRECTORY = os.path.join(PROJECT_ROOT, "data", "all_permissions")

# Path to all_explicit_permissions.txt file to store all explicit permissions
ALL_EXPLICIT_PERMISSIONS_FILE = os.path.join(ALL_PERMISSIONS_DIRECTORY, "all_explicit_permissions.txt")

# Path to all_wildcard_permissions.txt file to store all wildcard permissions
ALL_WILDCARD_PERMISSIONS_FILE = os.path.join(ALL_PERMISSIONS_DIRECTORY, "all_wildcard_permissions.txt")

# Path to wildcard_mapping.csv file that stores information which wilcard contains what explicit permissions
WILDCARD_MAPPING_FILE = os.path.join(ALL_PERMISSIONS_DIRECTORY, "wildcard_mapping.csv")

# Path to wildcard_sizes.csv file that stores the size of each wildcard permission
WILDCARD_SIZES_FILE = os.path.join(ALL_PERMISSIONS_DIRECTORY, "wildcard_sizes.csv")

# Path to log file that stores the terminal information
GET_ALL_PERMISSIONS_INFORMATION_FILE = os.path.join(ALL_PERMISSIONS_DIRECTORY, "get_all_permissions_information.txt")

# Traverse all permission md files in the azure permissions directory -> Return set of explicit permissions
def extract_explicit_permissions():
    # Empty set for all explicit permissions
    all_explicit_permissions = set()

    # Regex for explicit permissions (case-insensitive)
    explicit_pattern = re.compile(
        # Microsoft.<ProviderName>, where <ProviderName> allows A-Z, a-z
        r"Microsoft\.[A-Za-z]+"
        # Mandatory /{resourceType}, where <resourceType> allows A-Z, a-z, 0-9
        r"/[A-Za-z0-9]+"
        # Continuing with /
        # Then -> * -> Zero or many additional <entry/>, allowing A-Z, a-z, 0-9, ., -, _
        # After /providers/ -> There might be a new Microsoft.Insights entry with a "."
        r"/(?:[A-Za-z0-9.\-_]+/)*"
        # <action> which allows A-Z, a-z, 0-9
        r"[A-Za-z0-9]+",
        # In order to also match "microsoft" at the start
        re.IGNORECASE
    )

    # For each permission file, gather all explicit permissions not already added to all_explicit_permissions
    for category in os.listdir(AZURE_PERMISSIONS_DIRECTORY):
        path = os.path.join(AZURE_PERMISSIONS_DIRECTORY, category)
        with open(path, "r", encoding="utf-8") as md_file:
            content = md_file.read()
        # Find all matches
        raw_permissions = set(explicit_pattern.findall(content))
        # Normalize: lowercase and strip whitespace
        permissions = {p.strip().lower() for p in raw_permissions}
        # Add to master set
        for perm in permissions:
            all_explicit_permissions.add(perm)

    return all_explicit_permissions

# Traverse all built-in roles md files in the azure permissions directory
# -> Return set of wildcard permissions
# -> Check if additional explicit permissions are found, and return a new set of explicit permissions
def extract_wildcard_permissions(all_explicit_permissions):
    # Empty set for all wildcard permissions
    all_wildcard_permissions = set()

    # For each role md file, gather all wildcard permissions not already added to all_wildcard_permissions
    # For each role md file, check if it contains explicit permissions not already added to all_explicit_permissions
    for category in os.listdir(AZURE_BUILT_IN_ROLES_DIRECTORY):
        path = os.path.join(AZURE_BUILT_IN_ROLES_DIRECTORY, category)
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
                # get permissions of role
                permissions = data.get("permissions", [])
                # Permissions usually has len(permissions) = 1
                # However, in a few cases, len(permissions) = 2 as some roles have a second permission entry
                # which contains the ability to create and delete role assignments
                # Microsoft.Authorization/roleAssignments/write
                # Microsoft.Authorization/roleAssignments/delete
                if len(permissions) > 2:
                    print("Found a role with permissions size > 2.")
                    print("Built in roles: " + category)
                    print("Role name: " + data.get("roleName", []))
                    exit(1)
                elif len(permissions) < 1:
                    print("Found a role with permissions size < 1.")
                    print("Built in roles: " + category)
                    print("Role name: " + data.get("roleName", []))
                    exit(1)
                else:
                    # 1 - 2 iterations
                    for perms in permissions:
                        # Go through each permission type and check:
                        # Do the listed permissions contain a "*" -> Wildcard"
                        # Else: Is it already contained in all_explicit_permissions -> If not -> Add it!
                        all_perms = (
                                perms.get("actions", [])
                                + perms.get("notActions", [])
                                + perms.get("dataActions", [])
                                + perms.get("notDataActions", [])
                        )
                        for perm in all_perms:
                            perm = perm.strip().lower()
                            if "*" in perm:
                                all_wildcard_permissions.add(perm)
                            else:
                                if perm not in all_explicit_permissions:
                                    all_explicit_permissions.add(perm)
            except json.JSONDecodeError:
                print("Found invalid JSON block in category: " + category)
                exit(1)

    return all_wildcard_permissions, all_explicit_permissions

def main():
    # Check if the azure permission directory exists. If not -> error and exit
    if not os.path.isdir(AZURE_PERMISSIONS_DIRECTORY):
        print("The " + AZURE_PERMISSIONS_DIRECTORY + " directory is missing.")
        print("Did you run init_azure.py?")
        exit(1)

    # Check if the azure built-in roles directory exists. If not -> error and exit
    if not os.path.isdir(AZURE_BUILT_IN_ROLES_DIRECTORY):
        print("The " + AZURE_BUILT_IN_ROLES_DIRECTORY + " directory is missing.")
        print("Did you run init_azure.py?")
        exit(1)

    # If all_permissions dir does not exist -> Create, If exists -> Empty
    if not os.path.isdir(ALL_PERMISSIONS_DIRECTORY):
        # Command makedirs would also create data directory if missing
        # -> data directory should always exist, because init_azure was run before
        os.makedirs(ALL_PERMISSIONS_DIRECTORY, exist_ok=True)
    else:
        # If existing -> empty all_permissions directory
        for entry in os.listdir(ALL_PERMISSIONS_DIRECTORY):
            path = os.path.join(ALL_PERMISSIONS_DIRECTORY, entry)
            if os.path.isfile(path) or os.path.islink(path):
                os.unlink(path)
            elif os.path.isdir(path):
                shutil.rmtree(path)

    # Open file to write logs
    log_writer = open(GET_ALL_PERMISSIONS_INFORMATION_FILE, "w")

    # Set of all explicit permissions
    all_explicit_permissions = extract_explicit_permissions()

    number_explicit_permissions_found_in_permission_md_files = len(all_explicit_permissions)
    msg = "Extracted " + str(
        number_explicit_permissions_found_in_permission_md_files) + " explicit permissions from all permission markdown files."
    print(msg)
    log_writer.write(msg + "\n")

    # all_explicit_permissions is overwritten because there might be new explicit permissions found in the built-in roles
    all_wildcard_permissions, all_explicit_permissions = extract_wildcard_permissions(all_explicit_permissions)

    number_explicit_permissions = len(all_explicit_permissions)
    number_additional_explicit_permissions = number_explicit_permissions - number_explicit_permissions_found_in_permission_md_files
    msg = "Extracted " + str(number_additional_explicit_permissions) + " additional explicit permissions from traversing the built-in-roles markdown files."
    print(msg)
    log_writer.write(msg + "\n")
    msg = "-> Extracted a total of " + str(number_explicit_permissions) + " explicit permissions."
    print(msg)
    log_writer.write(msg + "\n")

    number_wildcard_permissions = len(all_wildcard_permissions)
    msg = "Extracted a total of " + str(number_wildcard_permissions) + " wildcard permissions " + "from traversing the built-in-roles markdown files."
    print(msg)
    log_writer.write(msg + "\n")
    log_writer.close()

    all_explicit_permissions = sorted(all_explicit_permissions)
    all_wildcard_permissions = sorted(all_wildcard_permissions)

    # Create mapping between wildcard and explicits
    wildcard_mapping: set[tuple[str, str]] = set()
    for wildcard_perm in all_wildcard_permissions:
            for explicit_perm in all_explicit_permissions:
                if fnmatch(explicit_perm, wildcard_perm):
                    wildcard_mapping.add((wildcard_perm, explicit_perm))

    wildcard_mapping = sorted(wildcard_mapping, key=lambda x: (x[0], x[1]))

    # Create sizes of wildcard permissions
    wildcard_counts = defaultdict(int)
    for wildcard_perm, explicit_perm in wildcard_mapping:
        wildcard_counts[wildcard_perm] += 1
    wildcard_sizes: set[tuple[str, int]] = {
        (wildcard, count) for wildcard, count in wildcard_counts.items()
    }

    # Write contents into all_explicit_permissions and all_wildcard_permissions files and wildcard_mapping file
    with open(ALL_EXPLICIT_PERMISSIONS_FILE, "w", encoding="utf-8") as expl_perm_txt:
        # Write all explicit permissions -> each permission per line
        for perm in all_explicit_permissions:
            expl_perm_txt.write(perm + "\n")
    with open(ALL_WILDCARD_PERMISSIONS_FILE, "w", encoding="utf-8") as wild_perm_txt:
        # Write all wildcard permissions -> each permission per line
        for perm in all_wildcard_permissions:
            wild_perm_txt.write(perm + "\n")
    with open(WILDCARD_MAPPING_FILE, "w", newline="", encoding="utf-8") as wild_mapping_csv:
        # Write wildcard-to-explicit mappings -> tuple per line
        writer = csv.writer(wild_mapping_csv)
        # Write header
        writer.writerow(["wildcard_name", "explicit_name"])
        # Write contents
        for wildcard, explicit in wildcard_mapping:
            writer.writerow([wildcard, explicit])
    with open(WILDCARD_SIZES_FILE, "w", newline="", encoding="utf-8") as wild_sizes_csv:
        # Write wildcard-to-size mappings -> tuple per line
        writer = csv.writer(wild_sizes_csv)
        # Write header
        writer.writerow(["wildcard_name", "size"])
        # Write contents
        for wildcard, size in wildcard_sizes:
            writer.writerow([wildcard, size])
    log_writer.close()
    print("As a next step, we recommend to run get_all_roles.py")

if __name__ == "__main__":
    main()