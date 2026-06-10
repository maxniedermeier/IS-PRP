##########################
## Inputs: ###############
## requested_permission: The requested permission, e.g. microsoft.database.table/query
## pa: PA relation (mapping role names to permission names).
## share_assigned_roles: How many roles of the RBAC model should be assigned to a requesting user (0, 25 or 50), in %
##########################
## Return: ###############
## not_assigned_roles: PA relation s.t.
## (a) no assigned role contains the requested permission or a wildcard of the requested permission.
## (b) the not assigned roles dont contain the permissions already assigned through assigned roles.
## (c) no empty roles.
## assigned_explicits: All already assigned explicit permissions, including transitive permissions through wildcards
##########################

from fnmatch import fnmatch
from pathlib import Path
import os
import csv

# Script is located at <project>/src/find_role.py -> get <project>
PROJECT_ROOT = Path(__file__).resolve().parent.parent

def orgmodel_calculator(requested_permission, pa, share_assigned_roles):
    # Unique set of permissions contained in the given PA relation
    permissions = {item[1] for item in pa}
    # Set of roles contained in the given PA relation, ordered alphabetically as in the pa relation
    roles = sorted({item[0] for item in pa})

    # most simple case, just return given PA relation and permissions
    if share_assigned_roles == 0:
        return pa, set()

    # Determine threshold in role counts, e.g. 10 if share_assigned_roles is 50 and there is a total of 20 roles
    threshold_count = round(len(roles) * (share_assigned_roles / 100))

    # Track roles and permissions we assign to the requesting user
    assigned_roles = set()
    directly_assigned_permissions = set()

    # Traverse roles and try to reach threshold
    # -> Get the assigned roles and the directly assigned permissions
    for role in roles:
        add_role = True
        # Get all permissions of this role
        permissions_of_role = {p for r, p in pa if r == role}

        # Skip roles containing the forbidden permission -> Do *not* assign this role to a user
        if requested_permission in permissions_of_role:
            add_role = False

        # Skip roles containing a wildcard of the forbidden permission
        for wildcard_permission in permissions_of_role:
            if "*" in wildcard_permission:
                if fnmatch(requested_permission, wildcard_permission):
                    add_role = False

        # Assign the role if it is valid
        if add_role:
            assigned_roles.add(role)
            # Update permission set with union
            directly_assigned_permissions |= permissions_of_role

        # Stop when threshold is met
        if len(assigned_roles) >= threshold_count:
            break

    # If there are wildcard permissions in the directly assigned permissions, also add any permission contained in the wildcard
    # Here, we only consider the permissions present in PA, not all explicit permissions existing in Microsoft cloud
    assigned_permissions = set(directly_assigned_permissions)
    for assigned_wildcard in directly_assigned_permissions:
        # Consider only wildcards
        if "*" in assigned_wildcard:
            for permission in permissions:
                if fnmatch(permission, assigned_wildcard):
                    assigned_permissions.add(permission)

    # Assemble not assigned roles (to be returned set)
    pa_not_assigned: set[tuple[str, str]] = set()
    for role in roles:
        # Now only consider unassigned roles
        if role not in assigned_roles:
            # Keep only the permissions of the role that are *not* assigned
            filtered_permissions = {p for r, p in pa if r == role and p not in assigned_permissions}
            # Add values to new pa, if there are no filtered permissions left -> Role is not added
            for value in filtered_permissions:
                pa_not_assigned.add((role, value))

    # Create set of *all* explicit permissions assigned
    assigned_explicits = set()
    # Path to wildcard mapping
    wildcard_mapping_file = os.path.join(PROJECT_ROOT, "data", "all_permissions", "wildcard_mapping.csv")
    # Check if file exists. If not -> error and exit
    if not os.path.isfile(wildcard_mapping_file):
        print("The " + wildcard_mapping_file + " file was not found.")
        print("Did you run get_all_permissions.py?")
        exit(1)

    for assigned_permission in assigned_permissions:
        if not "*" in assigned_permission:
            assigned_explicits.add(assigned_permission)
        else:
            # It is a wildcard -> Get *all* explicits matched
            with open(wildcard_mapping_file, "r", encoding="utf-8") as wildcard_mapping_csv:
                reader = csv.DictReader(wildcard_mapping_csv)
                # DictReader skips header
                for row in reader:
                    if row["wildcard_name"] == assigned_permission:
                        assigned_explicits.add(row["explicit_name"])

    # Return *not* assigned role-to-permission assignments, and all assigned explicit permissions
    return pa_not_assigned, assigned_explicits