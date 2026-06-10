#########################
# Traverses all output files in <project>/data/output/<category>/<type> for all <category> and <type> subdirs
# Output results are stored in a single xlsx file in the <project>/data/evaluation directory
#########################

from pathlib import Path, PureWindowsPath
import os
import shutil
import csv
from fnmatch import fnmatch
from collections import Counter
import pandas as pd
from openpyxl import Workbook
from unicodedata import category

from src.orgmodel_calculator import orgmodel_calculator

# Script is located at <project>/src/init_azure.py -> get <project>
PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Path to evaluation subdirectory
EVALUATION_DIRECTORY = os.path.join(PROJECT_ROOT, "data", "evaluation")
# Path to evaluation file
EVALUATION_FILE = os.path.join(EVALUATION_DIRECTORY, "evaluation.xlsx")
# Path to output directory
OUTPUT_DIRECTORY = os.path.join(PROJECT_ROOT, "data", "output")
# Path to requests_final directory
REQUESTS_FINAL_DIRECTORY = os.path.join(PROJECT_ROOT, "data", "requests", "requests_final")
# Path to the preprocessed_pa directory
PREPROCESSED_PA_DIRECTORY = os.path.join(PROJECT_ROOT, "data", "all_roles", "preprocessed_pa")
# Path to all_permissions directory
ALL_PERMISSIONS_DIRECTORY = os.path.join(PROJECT_ROOT, "data", "all_permissions")
# Path to all_roles directory
ALL_ROLES_DIRECTORY = os.path.join(PROJECT_ROOT, "data", "all_roles")

# Sending the same request N_MAX times (should be the same value as in watsonx_runner.py)
N_MAX = 5

# Cache for storing the orgmodel_calculator results -> You not want to calculate those multiple times because of performance
cache = {}

# Traverse all subdirs in the output directory and return the paths as a set
def get_all_output_paths():
    base = Path(OUTPUT_DIRECTORY)
    csv_paths = set(base.rglob("*.csv"))
    if len(csv_paths) == 0:
        print("No csv files were found in the /data/output directory.")
        exit(1)
    else:
        return csv_paths

# Sum up the correct permission translations in the output file
def get_number_of_correct_permission_translations(output_path, solution_mapping):
    # number of correct permission translations
    correct_permissions = 0
    with open(output_path, newline='', encoding='utf-8') as output_csv:
        reader = csv.DictReader(output_csv, delimiter=';')
        for row in reader:
            request = row["request"]
            translated_permission = row["permission"]
            # Correct translation according to solution_mapping
            if translated_permission == solution_mapping.get(request):
                correct_permissions += 1
            # It could happen that the required permission is contained in the translated wildcard permission
            else:
                # Translated permission is wildcard
                if "*" in translated_permission:
                    # The translated wildcard contains the required permission
                    if fnmatch(solution_mapping.get(request), translated_permission):
                        correct_permissions += 1
    return correct_permissions

# Sum of the correct role suggestions in the output file
def get_number_of_correct_role_suggestions(output_path, solution_mapping, original_pa, polished_name_output_file):
    # number of correct role suggestions
    correct_roles = 0
    with open(output_path, newline='', encoding='utf-8') as output_csv:
        reader = csv.DictReader(output_csv, delimiter=';')
        for row in reader:
            correct_role = False
            request = row["request"]
            suggested_role = row["role"]
            # Correct translation according to solution_mapping
            required_permission = solution_mapping.get(request)
            # Modify pa as previously done in watsonx_runner
            factor = 30 if "30%Ra" in polished_name_output_file else 0
            p = PureWindowsPath(polished_name_output_file)
            category_name = p.parts[0]
            # Create the cache key -> Used for all experiments with role assignments
            cache_key = (required_permission, category_name, factor)
            if factor == 30:
                if cache_key in cache:
                    pa, assigned_explicits = cache[cache_key]
                else:
                    pa, assigned_explicits = orgmodel_calculator(required_permission, original_pa, factor)
                    cache[cache_key] = (pa, assigned_explicits)
            else:
                # Fast return
                pa, assigned_explicits = orgmodel_calculator(required_permission, original_pa, factor)
            # All permissions directly assigned to the suggested role
            permissions_of_suggested_role = {p for r, p in pa if r == suggested_role}
            # Check if the required permission is contained in the suggested role
            if required_permission in permissions_of_suggested_role:
                correct_role = True
            # It could happen that the required permission is contained in a wildcard within the role
            else:
                # Check if any permission in the role...
                for wildcard_perm in permissions_of_suggested_role:
                    # Which is a wildcard permission...
                    if "*" in wildcard_perm:
                        # Covers the required permission
                        if fnmatch(required_permission, wildcard_perm):
                            correct_role = True
            if correct_role:
                correct_roles += 1

    return correct_roles

# Return precision sums (consistency values) for both permission translations and role suggestions
def get_precision_sums(output_path):
    df = pd.read_csv(output_path, delimiter=';')
    # Init result counters
    precision_permission_sum = 0
    precision_role_sum = 0
    # Group by request
    for request, group in df.groupby('request'):
        # For each request, count all the translated permissions and suggested roles, including none
        permission_counter = Counter(group['permission'])
        role_counter = Counter(group['role'])

        # Get the most common permission count -> most_common(1) -> single most common item
        # -> [0] first (permission, count) tuple (most common permission) -> [1] selects count
        most_common_permission_count = permission_counter.most_common(1)[0][1]
        # According to metrics, always add the (most common / number of iterations) e.g. 4/5 or 3/5
        precision_permission_sum += most_common_permission_count / N_MAX

        # Get the most common role count -> most_common(1) -> single most common item
        # -> [0] first (role, count) tuple (most common role) -> [1] selects count
        most_common_role_count = role_counter.most_common(1)[0][1]
        # According to metrics, always add the (most common / number of iterations) e.g. 4/5 or 3/5
        precision_role_sum += most_common_role_count / N_MAX

    return precision_permission_sum, precision_role_sum

# Return sum of hallucinated permissions and summed up hallucinated roles
def get_hallucination_sums(output_path, all_explicits, all_wildcards, all_role_names):
    # Init result counters
    hallucinated_permissions = 0
    hallucinated_roles = 0
    with open(output_path, mode='r', newline='', encoding='utf-8') as output_csv:
        reader = csv.DictReader(output_csv, delimiter=';')
        # Count...
        for row in reader:
            permission = row['permission']
            role = row['role']
            # ...how often a permission decision does *not* appear in the all_explicits and all_wildcards files
            if permission != "none":
                if permission not in all_explicits:
                    if permission not in all_wildcards:
                        hallucinated_permissions += 1
            # ... how often a role does not appear in the set of all roles
            if role != "none":
                if role not in all_role_names:
                    hallucinated_roles += 1
    return hallucinated_permissions, hallucinated_roles

# Return modesty sums for both permission translations and role suggestions
def get_modesty_sums(output_path):
    # Init result counters
    none_in_permissions = 0
    none_in_roles = 0
    with open(output_path, mode='r', newline='', encoding='utf-8') as output_csv:
        reader = csv.DictReader(output_csv, delimiter=';')
        # Simply count how often none appears
        for row in reader:
            if row['permission'] == "none":
                none_in_permissions += 1
            if row['role'] == "none":
                none_in_roles += 1

    return none_in_permissions, none_in_roles

# Return size of a certain role
def get_role_size(permissions_of_role, wildcard_mapping, assigned_explicits):
    # Gather all explicits of role
    all_explicits_of_role = set()
    # First, trivially, add all permissions of this role which are not a wildcard
    for perm in permissions_of_role:
        if "*" not in perm:
            all_explicits_of_role.add(perm)

    # Now add all the explicits permissions matched through a wildcard
    for wildcard_perm in permissions_of_role:
        if "*" in wildcard_perm:
            for wildcard_explicit_tuple in wildcard_mapping:
                if wildcard_explicit_tuple[0] == wildcard_perm:
                    # Check that this permission is not already assigned through the orgmodel_calculator
                    if wildcard_explicit_tuple[1] not in assigned_explicits:
                        all_explicits_of_role.add(wildcard_explicit_tuple[1])

    return len(all_explicits_of_role)

# Return additional permissions of correctly suggested roles, and additional permissions of optimal roles
def get_additional_permissions(output_path, solution_mapping, original_pa, wildcard_mapping, polished_name_output_file):
    # Init result counters
    additional_perms_role_accurate = 0
    additional_perms_role_accurate_optimal = 0
    # Traverse output file
    with (open(output_path, mode='r', newline='', encoding='utf-8') as output_csv):
        reader = csv.DictReader(output_csv, delimiter=';')
        for row in reader:
            correct_role = False
            request = row["request"]
            suggested_role = row["role"]
            # Correct translation according to solution_mapping
            required_permission = solution_mapping.get(request)
            # Modify pa as previously done in watsonx_runner
            factor = 30 if "30%Ra" in polished_name_output_file else 0
            p = PureWindowsPath(polished_name_output_file)
            category_name = p.parts[0]
            # Create the cache key -> Used for all experiments with role assignments
            cache_key = (required_permission, category_name, factor)
            if factor == 30:
                if cache_key in cache:
                    pa, assigned_explicits = cache[cache_key]
                else:
                    print("Could not find cache key: " + str(cache_key) + " although it should exist.")
                    exit(1)
            else:
                # Fast return
                pa, assigned_explicits = orgmodel_calculator(required_permission, original_pa, factor)
            # Get the size of the required permission
            if "*" not in required_permission:
                size_required_permission = 1
            else:
                # Required permission is a wildcard
                new_expl_in_wildcard_perm = set()
                for wildcard_explicit_tuple in wildcard_mapping:
                    if wildcard_explicit_tuple[0] == required_permission:
                        # Only consider explicit permissions not already assigned
                        if wildcard_explicit_tuple[1] not in assigned_explicits:
                            new_expl_in_wildcard_perm.add(wildcard_explicit_tuple[1])
                size_required_permission = len(new_expl_in_wildcard_perm)
            # All permissions directly assigned to the suggested role
            permissions_of_suggested_role = {p for r, p in pa if r == suggested_role}
            # Check if the required permission is directly contained in the suggested role
            if required_permission in permissions_of_suggested_role:
                correct_role = True
            # It could happen that the required permission is contained in a wildcard within the role
            else:
                # Check if any permission in the role...
                for wildcard_perm in permissions_of_suggested_role:
                    # Which is a wildcard permission...
                    if "*" in wildcard_perm:
                        # Covers the required permission
                        if fnmatch(required_permission, wildcard_perm):
                            correct_role = True
            if correct_role:
                # Add additional permissions of the correct, suggested role
                additional_perms_role_accurate += (
                    (get_role_size(permissions_of_suggested_role, wildcard_mapping, assigned_explicits) - size_required_permission)
                )
                # Get all correct role names
                names_of_candidate_roles = set()
                # Traverse all roles and their assigned permissions
                all_roles = {r for r,p in pa}
                for role in all_roles:
                    # Permissions of this role
                    permissions_of_role = {p for r, p in pa if r == role}
                    # Required permission is directly assigned to the role
                    if required_permission in permissions_of_role:
                        names_of_candidate_roles.add(role)
                    else:
                        # Check if an assigned wildcard contains the required permission
                        for wildcard_perm in permissions_of_role:
                            if "*" in wildcard_perm:
                                if fnmatch(required_permission, wildcard_perm):
                                    names_of_candidate_roles.add(role)
                # Get the sizes of all correct roles
                valid_sizes = set()
                for candidate_role in names_of_candidate_roles:
                    permissions_of_candidate_role = {p for r, p in pa if r == candidate_role}
                    size_of_candidate_role = get_role_size(permissions_of_candidate_role, wildcard_mapping, assigned_explicits)
                    valid_sizes.add(size_of_candidate_role)
                # Add additional permissions of the smallest correct role
                additional_perms_role_accurate_optimal += (min(valid_sizes) - size_required_permission)

    return additional_perms_role_accurate, additional_perms_role_accurate_optimal

def evaluation_process():
    print("Starting evaluation process.")

    # Check if output, requests_final, preprocessed_pa and all_permissions dirs exist. If not -> Error
    if not os.path.isdir(OUTPUT_DIRECTORY):
        print("/data/output directory was not found. Abort.")
        exit(1)
    if not os.path.isdir(REQUESTS_FINAL_DIRECTORY):
        print("/data/requests/requests_final directory was not found. Abort.")
        exit(1)
    if not os.path.isdir(PREPROCESSED_PA_DIRECTORY):
        print("/data/all_roles/preprocessed_pa directory was not found. Abort.")
        exit(1)
    if not os.path.isdir(ALL_PERMISSIONS_DIRECTORY):
        print("/data/all_permissions directory was not found. Abort.")
        exit(1)
    if not os.path.isdir(ALL_ROLES_DIRECTORY):
        print("/data/all_roles directory was not found. Abort.")
        exit(1)

    # If evaluation directory does not exist -> Create. If it exists -> Clean up
    if not os.path.isdir(EVALUATION_DIRECTORY):
        # Command makedirs would also create data directory if missing
        os.makedirs(EVALUATION_DIRECTORY, exist_ok=True)
        print("The /data/evaluation directory was missing, but was now created.")

    else:
        # If existing -> empty clone_repo_date directory
        for entry in os.listdir(EVALUATION_DIRECTORY):
            path = os.path.join(EVALUATION_DIRECTORY, entry)

            if os.path.isfile(path) or os.path.islink(path):
                os.unlink(path)
            elif os.path.isdir(path):
                shutil.rmtree(path)

    # Construct Excel file
    wb = Workbook()
    ws = wb.active
    # Static header list added at the start of the XLSX file
    headers = [
        "Output File Name",
        "Permission Accuracy",
        "Role Accuracy",
        "Permission Precision",
        "Role Precision",
        "Permission Hallucination",
        "Role Hallucination",
        "Permission Modesty",
        "Role Modesty",
        "Relative PoLP Violation",
        "Total PoLP Violation"
    ]
    ws.append(headers)

    # Retrieve all permission information from the all_permissions directory
    all_explicits = set()
    with open(os.path.join(ALL_PERMISSIONS_DIRECTORY, "all_explicit_permissions.txt"), "r", newline="", encoding="utf-8") as all_explicit_permissions_txt:
        content = all_explicit_permissions_txt.read()
        for row in content.splitlines():
            all_explicits.add(row)
    all_wildcards = set()
    with open(os.path.join(ALL_PERMISSIONS_DIRECTORY, "all_wildcard_permissions.txt"), "r", newline="", encoding="utf-8") as all_wildcard_permissions_txt:
        content = all_wildcard_permissions_txt.read()
        for row in content.splitlines():
            all_wildcards.add(row)
    wildcard_mapping = set()
    with open(os.path.join(ALL_PERMISSIONS_DIRECTORY, "wildcard_mapping.csv"), "r", newline="", encoding="utf-8") as wildcard_mapping_csv:
        reader = csv.DictReader(wildcard_mapping_csv)
        for row in reader:
            wildcard_mapping.add((row["wildcard_name"], row["explicit_name"]))
    # Retrieve name of all roles
    all_role_names = set()
    with open(os.path.join(ALL_ROLES_DIRECTORY, "roles_data.csv"), "r", newline="", encoding="utf-8") as all_roles_csv:
        reader = csv.DictReader(all_roles_csv)
        for row in reader:
            all_role_names.add(row["role_name"])
    # Get the paths to all output csv files generated from watsonx_runner.py
    all_output_paths = get_all_output_paths()
    all_output_paths = sorted(all_output_paths)
    # Traversing all output csv files
    for output_path in all_output_paths:
        # Traverse the requests final file and fill solution mapping and number_of_requests
        requests_final_file_path = os.path.join(REQUESTS_FINAL_DIRECTORY, output_path.parts[-3] + ".csv")
        solution_mapping = {}
        number_of_requests = 0
        with open(requests_final_file_path, "r", newline="", encoding="utf-8") as requests_final_csv:
            reader = csv.DictReader(requests_final_csv)
            for row in reader:
                solution_mapping[row["request"]] = row["permission_name"]
                number_of_requests += 1
        # Traverse the pa file in preprocessed_pa dir and fill roles
        pa_file_path = os.path.join(PREPROCESSED_PA_DIRECTORY, output_path.parts[-3] + ".csv")
        original_pa: set[tuple[str, str]] = set()
        with open(pa_file_path,"r", newline="", encoding="utf-8") as pa_csv:
            reader = csv.DictReader(pa_csv)
            for row in reader:
                original_pa.add((row["role_name"], row["permission_name"]))

        polished_name_output_file = str(Path(*output_path.parts[-3:])) # WindowsPath('<category>/<type>/<something>.csv')
        print("Currently evaluating: " + polished_name_output_file)
        correct_permission_translations = get_number_of_correct_permission_translations(output_path, solution_mapping)
        correct_role_suggestions = (
            get_number_of_correct_role_suggestions(output_path, solution_mapping, original_pa, polished_name_output_file))
        precision_permission_sum, precision_role_sum = get_precision_sums(output_path)
        hallucination_permission_sum, hallucination_role_sum = get_hallucination_sums(output_path, all_explicits, all_wildcards, all_role_names)
        modesty_permission_sum, modesty_role_sum = get_modesty_sums(output_path)
        additional_perms_role_accurate, additional_perms_role_accurate_optimal = (
            get_additional_permissions(output_path, solution_mapping, original_pa, wildcard_mapping, polished_name_output_file))

        # Calculate metrics and put into row
        row = [
            polished_name_output_file,
            # Share of all correct permission translations
            str(correct_permission_translations / (number_of_requests * N_MAX)),
            # Share of all correct role suggestions
            str(correct_role_suggestions / (number_of_requests * N_MAX)),
            # Average Precision values across all requests
            str(precision_permission_sum / number_of_requests),
            str(precision_role_sum / number_of_requests),
            # Share of hallucinated values
            str(hallucination_permission_sum / (number_of_requests * N_MAX)),
            str(hallucination_role_sum / (number_of_requests * N_MAX)),
            # Share of modesty values
            str(modesty_permission_sum / (number_of_requests * N_MAX)),
            str(modesty_role_sum / (number_of_requests * N_MAX)),
            # Across all requests with a correct role suggestion, sum up additional permissions
            # Across all requests with a correct role suggestion, sum up additional permissions of optimal role suggestions
            # Then, divide A through B
            str(additional_perms_role_accurate / additional_perms_role_accurate_optimal),
            # NEW: Across all correct role suggestions, calculate the average additional permissions assigned
            str(additional_perms_role_accurate / correct_role_suggestions)
        ]

        ws.append(row)

    wb.save(EVALUATION_FILE)

    print("Finished the evaluation process.")