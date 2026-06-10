##########################
## Inputs: ###############
## response_permission: The request-to-permission translation by the text or embedding model.
## original_pa: PA relation (mapping role names to permission names).
## pa: PA relation after removing roles and permissions assigned to the user.
## share_assigned_roles: How many roles of the RBAC model should be assigned to a requesting user (0, 25 or 50), in %
##########################
## Return: ###############
## none if the permission is none or not in PA (hallucinated or already assigned).
## The smallest role that contains the requested permission.
##########################

from fnmatch import fnmatch
import os
from pathlib import Path
import csv

# Script is located at <project>/src/find_role.py -> get <project>
PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Helper to compute role sizes
def get_role_size(role_name, pa, assigned_explicits):
    # Path to wildcard mapping
    wildcard_mapping_file = os.path.join(PROJECT_ROOT, "data", "all_permissions", "wildcard_mapping.csv")
    # Check if file exists. If not -> error and exit
    if not os.path.isfile(wildcard_mapping_file):
        print("The " + wildcard_mapping_file + " file was not found.")
        print("Did you run get_all_permissions.py?")
        exit(1)

    # All permissions of role according to current pa relation
    permissions_of_role = {p for r, p in pa if r == role_name}
    # Gather all explicits of role
    all_explicits_of_role = set()
    # First, trivially, add all permissions of this role which are not a wildcard
    for perm in permissions_of_role:
        if "*" not in perm:
            all_explicits_of_role.add(perm)
    # Now add all the explicits permissions matched through a wildcard
    for wildcard_perm in permissions_of_role:
        if "*" in wildcard_perm:
            with open(wildcard_mapping_file, "r", encoding="utf-8") as wildcard_mapping_csv:
                reader = csv.DictReader(wildcard_mapping_csv)
                # DictReader skips header
                for row in reader:
                    if row["wildcard_name"] == wildcard_perm:
                        # Check that this permission is not already assigned through the orgmodel_calculator
                        if row["explicit_name"] not in assigned_explicits:
                            all_explicits_of_role.add(row["explicit_name"])

    return len(all_explicits_of_role)

def find_role(response_permission, original_pa, pa, assigned_explicits):
    # Case 1: When using an LLM for permission translations, it may return none instead of a permission.
    # If response_permission is none -> Return none
    if response_permission == "none":
        return "none"

    # Case 2: When using an LLM for permission translations, it may return a permission that does not exist in original_pa
    # This means that the permission is hallucinated
    # Then, a suitable role can not be found
    # NOTE: Logically, this is not required, because if it is not in original_pa, then it also is not in pa (next step)
    original_permissions = {item[1] for item in original_pa}
    if response_permission not in original_permissions:
        return "none"

    # Case 3: When using an LLM for permission translations, it could theoretically (!)
    # return a permission that exists in the original_pa but is already assigned by running orgmodel_calculator

    # We already know the permission exists in the original permissions
    # Now we check if the permission exists in the used permissions
    permissions = {item[1] for item in pa}
    if response_permission not in permissions:
        return "none"

    # Case 4: Permission exists in original_pa and is not yet assigned to the user -> return smallest role
    # Find all role candidates in roles that contain this permission or a correct wildcard
    candidate_roles = set()
    roles = {item[0] for item in pa}
    for role in roles:
        add_role_as_candidate = False
        permissions_of_role = {p for r, p in pa if r == role}
        # if the translated permission is directly contained in the role perms
        if response_permission in permissions_of_role:
            # then consider this role as a candidate
            add_role_as_candidate = True
        # if any wildcard contains this permission
        for wildcard_perm in permissions_of_role:
            if "*" in wildcard_perm:
                if fnmatch(response_permission, wildcard_perm):
                    # then consider this role as a candidate
                    add_role_as_candidate = True
        if add_role_as_candidate:
            candidate_roles.add(role)

    # The smallest role (fewest permissions)
    # For each role in candidate_roles -> get_role_size
    # Then, pick role with smallest returned value.
    smallest_role = min(candidate_roles, key=lambda r: get_role_size(r, pa, assigned_explicits))

    # Return the smallest role
    return smallest_role