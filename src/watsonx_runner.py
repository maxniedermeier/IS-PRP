#########################
# After finishing all data preprocessing steps, this script is the main script for starting the experiments.
# When running this script, you are to decide which data set and experiment type(s) should be used.
# Calls orgmodel_calculator.py, find_role.py -> Do not run these scripts manually.
# Output can be found in /data/output/{category}
#########################

import random
from collections import defaultdict
from fnmatch import fnmatch
from pathlib import Path
import os
import shutil
import csv
import numpy as np
import pandas as pd

from sklearn.metrics.pairwise import cosine_similarity
from ibm_watsonx_ai import APIClient
from ibm_watsonx_ai.foundation_models import ModelInference
from ibm_watsonx_ai.foundation_models import Embeddings

# Custom scripts
from orgmodel_calculator import orgmodel_calculator
from find_role import find_role

# Script is located at <project>/src/watsonx_runner.py -> get <project>
PROJECT_ROOT = Path(__file__).resolve().parent.parent

# watsonx configuration
CREDENTIALS = {
    "url": "<region-endpoint",  # Removed
    "apikey": "<api-key>"  # Removed
}

PROJECT_ID = "<project-id>"  # Removed

# Create client
CLIENT = APIClient(CREDENTIALS)

# Associate client with watsonx project
CLIENT.set.default_project(PROJECT_ID)

print("Connected successfully to watsonx.ai project:", PROJECT_ID)

# Output all available models
# CLIENT.foundation_models.TextModels.show()
# CLIENT.foundation_models.EmbeddingModels.show()

# Paths
ALL_PERMISSIONS_DIRECTORY = os.path.join(PROJECT_ROOT, "data", "all_permissions")
ALL_ROLES_DIRECTORY = os.path.join(PROJECT_ROOT, "data", "all_roles")
ALL_ROLES_PREPROCESSED_DIRECTORY = os.path.join(PROJECT_ROOT, "data", "all_roles", "preprocessed_pa")
REQUESTS_FINAL_DIRECTORY = os.path.join(PROJECT_ROOT, "data", "requests", "requests_final")
OUTPUT_DIRECTORY = os.path.join(PROJECT_ROOT, "data", "output")

# Models
GRANITE_EMBEDDING_ID = "ibm/granite-embedding-278m-multilingual"
MISTRAL_SMALL_ID = "mistralai/mistral-small-3-1-24b-instruct-2503"
MISTRAL_MEDIUM_ID = "mistralai/mistral-medium-2505"

# Sending the same request N_MAX times (all experiments)
N_MAX = 5
# Target assigned roles in % for orgmodel_calculator.py (A, N experiments)
PERC_ASSIGNED_ROLES = [0,30]
# Models used (B, A experiments)
MODELS = [MISTRAL_SMALL_ID,MISTRAL_MEDIUM_ID]
# Number of Permissions shown in the system prompt (A experiments)
NUM_PERMISSIONS = [5,10]

# Baseline: Query an LLM with no RBAC model information about a permission
# Return lowercased, stripped permission result
def get_permission_from_plain_text_model(model, request, category, explicit_permission_1, explicit_permission_2, wildcard_permission):
    system_prompt = f"""
You are an expert decision support system for access control.
You will receive a user request in natural language.
Your task is to identify and output the single most likely permission name that matches the user’s request.

RULES:
- Consider only Azure permissions that exist in at least one of the built-in roles for {category}
- Examples for permission names: {explicit_permission_1} or {explicit_permission_2}
- You are allowed to output a wildcard permission. Example: {wildcard_permission}
- If no permission clearly matches, or if you are uncertain, then the output is: none
- Output exactly one line: Either a permission name or none. Do not output any explanations, formatting, punctuation, or newlines after your answer.

IMPORTANT:
- You are not in a conversation. Do not simulate users or continue with further examples.
- Do always terminate after the first output line.
- After outputting the result, STOP GENERATING immediately.
"""

    # Combine system and user context into one prompt
    prompt = f"System:{system_prompt}\nUser: {request}\nAssistant:"
    # Let model generate and retrieve a permission
    prompt_result = model.generate(prompt=prompt)
    permission_result = prompt_result["results"][0]["generated_text"]
    # Remove leading blank spaces if there are any, consider only the first line of output
    # lstrip would theoretically remove blank first line
    # split("\n")[0] takes first line of output only
    # strip() removes whitespaces from both sides
    permission_result = permission_result.lstrip().split("\n")[0].strip()
    permission_result = permission_result.lower()

    return permission_result


# Baseline: Query an LLM with no RBAC model information about a role
# Return lowercased, stripped role result
def get_role_from_plain_text_model(model, request, category, role_1, role_2, invalid_roles):
    system_prompt = f"""
You are an expert decision support system for access control.
You will receive a user request in natural language.
Your task is to identify and output the single most likely role name that contains the required permission.

RULES:
- Consider only Azure roles that are part of the built-in roles for {category}
- Examples for role names: {role_1} or {role_2}
- If no role clearly matches, or if you are uncertain, then the output is: none
- Do not suggest any of the INVALID ROLES, which are provided below.
- Output exactly one line: Either a role name or none. Do not output any explanations, formatting, punctuation, or newlines after your answer.

INVALID ROLES:
{invalid_roles}

PRINCIPLE OF LEAST PRIVILEGE:
- Apply the Principle of Least Privilege: If multiple roles contain the required permission, recommend the one with the fewest assigned permissions.
- If multiple roles contain the required permission, but you cannot determine which role has the fewest permissions, suggest any role that includes the permission.

IMPORTANT:
- You are not in a conversation. Do not simulate users or continue with further examples.
- Do always terminate after the first output line.
- After outputting the result, STOP GENERATING immediately.
"""
    # Combine system and user context into one prompt
    prompt = f"System:{system_prompt}\nUser: {request}\nAssistant:"
    # Let model generate and retrieve a role
    prompt_result = model.generate(prompt=prompt)
    role_result = prompt_result["results"][0]["generated_text"]
    # Remove leading blank spaces if there are any, consider only the first line of output
    # lstrip would theoretically remove blank first line
    # split("\n")[0] takes first line of output only
    # strip() removes whitespaces from both sides
    role_result = role_result.lstrip().split("\n")[0].strip()
    role_result = role_result.lower()

    return role_result

# RBAC-Aware: Query an LLM with RBAC model information about a permission
# Return lowercased, stripped permission result
def get_permission_from_aware_model(model, request, topk_permissions):
    system_prompt = f"""
You are an expert decision support system for access control.
You will receive a user request in natural language.
Your task is to identify and output the single most likely permission name that matches the user’s request.

RULES:
- Consider only Azure permissions that are listed in the AVAILABLE PERMISSIONS, which are provided below.
- If no permission clearly matches, or if you are uncertain, then the output is: none
- Output exactly one line: Either a permission name or none. Do not output any explanations, formatting, punctuation, or newlines after your answer.

AVAILABLE PERMISSIONS:
{topk_permissions}

IMPORTANT:
- You are not in a conversation. Do not simulate users or continue with further examples.
- Do always terminate after the first output line.
- After outputting the result, STOP GENERATING immediately.
"""

    # Combine system and user context into one prompt
    prompt = f"System:{system_prompt}\nUser: {request}\nAssistant:"
    # Let model generate and retrieve a permission
    prompt_result = model.generate(prompt=prompt)
    permission_result = prompt_result["results"][0]["generated_text"]
    # Remove leading blank spaces if there are any, consider only the first line of output
    # lstrip would theoretically remove blank first line
    # split("\n")[0] takes first line of output only
    # strip() removes whitespaces from both sides
    permission_result = permission_result.lstrip().split("\n")[0].strip()
    permission_result = permission_result.lower()

    return permission_result

# RBAC-Aware: Query an LLM with RBAC model information about a role
# Return lowercased, stripped role result
def get_role_from_aware_model(model, request, pa, candidate_roles_raw, assigned_explicits):
    # Load wildcard sizes
    wildcard_sizes_path = os.path.join(ALL_PERMISSIONS_DIRECTORY, "wildcard_sizes.csv")
    wildcard_sizes = pd.read_csv(wildcard_sizes_path)
    wildcard_sizes_map = dict(zip(wildcard_sizes['wildcard_name'], wildcard_sizes['size']))
    # Mapping all roles -> their assigned permissions
    role_permissions = defaultdict(list)
    for role_name, permission_name in pa:
        role_permissions[role_name].append(permission_name)
    # Only consider top roles, bring them in correct format
    role_lines = []
    for role_name in candidate_roles_raw:
        # Get permissions of roles
        perms = role_permissions.get(role_name, [])
        perms_with_sizes = []
        #  For each permission
        for perm in perms:
            # If it is a wildcard permission...
            if perm in wildcard_sizes_map:
                # How many permissions are already mapped?
                matched_assigned_explicits = sum(1 for a_e in assigned_explicits if fnmatch(a_e, perm))
                # Then add the number of new permissions by using this wildcard
                perms_with_sizes.append(f"{perm} (size: {wildcard_sizes_map[perm] - matched_assigned_explicits})")
            # If it is not a wildcard permission...
            else:
                # Then just add the permission
                perms_with_sizes.append(perm)
        # A role line is the role name and its assigned permissions
        role_lines.append(
            f"{role_name}, assigned permissions: [{', '.join(perms_with_sizes)}]"
        )
    # One role per line
    candidate_roles = "\n".join(role_lines)

    system_prompt = f"""
You are an expert decision support system for access control.
You will receive a user request in natural language.
Your task is to identify and output the single most likely role name that contains the required permission.

RULES:
- Consider only Azure roles that are listed in the CANDIDATE ROLES, which are provided below.
- If no role clearly matches, or if you are uncertain, then the output is: none
- Output exactly one line: Either a role name or none. Do not output any explanations, formatting, punctuation, or newlines after your answer.

CANDIDATE ROLES:
{candidate_roles}

PRINCIPLE OF LEAST PRIVILEGE:
- Apply the Principle of Least Privilege: If multiple roles contain the required permission, recommend the one with the fewest assigned permissions.
- If multiple roles contain the required permission, but you cannot determine which role has the fewest permissions, suggest any role that includes the permission.
- The sizes of wildcard permissions are indicated in parentheses after the wildcard.

IMPORTANT:
- You are not in a conversation. Do not simulate users or continue with further examples.
- Do always terminate after the first output line.
- After outputting the result, STOP GENERATING immediately.
"""

    # Combine system and user context into one prompt
    prompt = f"System:{system_prompt}\nUser: {request}\nAssistant:"
    # Let model generate and retrieve a role
    prompt_result = model.generate(prompt=prompt)
    role_result = prompt_result["results"][0]["generated_text"]
    # Remove leading blank spaces if there are any, consider only the first line of output
    # lstrip would theoretically remove blank first line
    # split("\n")[0] takes first line of output only
    # strip() removes whitespaces from both sides
    role_result = role_result.lstrip().split("\n")[0].strip()
    role_result = role_result.lower()

    return role_result

# Return 2 random explicit permissions from the /all_roles/preprocessed_pa/{category}.csv
def get_permission_examples(category):
    all_roles_preprocessed_path = os.path.join(ALL_ROLES_DIRECTORY, "preprocessed_pa", category)
    explicit_permissions = set()

    with open(all_roles_preprocessed_path, mode="r", newline="", encoding="utf-8") as all_roles_preprocessed_csv:
        reader = csv.DictReader(all_roles_preprocessed_csv)
        for row in reader:
            if "*" not in row["permission_name"]:
                explicit_permissions.add(row["permission_name"])

    if len(explicit_permissions) < 2:
        print(
            "List of found explicit permissions < 2. Cannot retrieve two random explicit permissions and put these into the system prompt.")
        print("Category: " + category)
        exit(1)

    rng = random.Random(42)  # determ. seed
    explicit_permissions = list(explicit_permissions)
    return tuple(rng.sample(explicit_permissions, 2))

# Return random wildcard permission found in /all_roles/preprocessed_pa/{category}.csv
def get_wildcard_example(category):
    all_roles_preprocessed_path = os.path.join(ALL_ROLES_DIRECTORY, "preprocessed_pa", category)
    wildcard_permissions = set()

    with open(all_roles_preprocessed_path, mode="r", newline="", encoding="utf-8") as all_roles_preprocessed_csv:
        reader = csv.DictReader(all_roles_preprocessed_csv)
        for row in reader:
            if "*" in row["permission_name"]:
                wildcard_permissions.add(row["permission_name"])

    if not wildcard_permissions:
        print(
            "List of found wildcard permissions < 1. Cannot retrieve a random wildcard permission and put it into the system prompt.")
        print("Category: " + category)
        exit(1)

    rng = random.Random(42)  # determ. seed
    wildcard_permissions = list(wildcard_permissions)
    return rng.choice(wildcard_permissions)

# Return 2 random roles from roles_data.csv (roles that are a part of the category only)
def get_role_examples(category):
    roles_data_path = os.path.join(ALL_ROLES_DIRECTORY, "roles_data.csv")

    with open(roles_data_path, mode="r", newline="", encoding="utf-8") as roles_data_csv:
        reader = csv.DictReader(roles_data_csv)
        roles = []
        for row in reader:
            if row["category"] == category + ".md":
                if row["deny_operations"] == "False":
                    roles.append(row["role_name"])

    if len(roles) < 2:
        print(
            "List of found roles < 2. Cannot retrieve two random roles with no deny operations and put these into the system prompt.")
        print("Category: " + category)
        exit(1)

    rng = random.Random(42)  # determ. seed
    return tuple(rng.sample(roles, 2))

# Return all invalid roles (roles with deny operations) from roles_data.csv (roles that are part of the category only)
def get_invalid_roles(category):
    roles_data_path = os.path.join(ALL_ROLES_DIRECTORY, "roles_data.csv")

    with open(roles_data_path, mode="r", newline="", encoding="utf-8") as roles_data_csv:
        reader = csv.DictReader(roles_data_csv)
        invalid_roles = []
        for row in reader:
            if row["category"] == category + ".md":
                if row["deny_operations"] == "True":
                    invalid_roles.append(row["role_name"])

    return invalid_roles

# Create Experiment Type Subdirectory
def create_type_subdirectory(output_entry_subdirectory, experiment_type):
    # Create output/{data_choice}/{type} directory if not already existing
    type_dir_path = os.path.join(output_entry_subdirectory, str(experiment_type))
    if not os.path.isdir(type_dir_path):
        # Command makedirs would also create data/output/{data_choice} directory if missing
        os.makedirs(type_dir_path, exist_ok=True)
        print("The " + type_dir_path + " directory was missing, but was now created.")
    else:
        # If subdirectory is already existing -> Empty it!
        print("The " + type_dir_path + " directory already exists and thus we empty it.")
        for entry in os.listdir(type_dir_path):
            path = os.path.join(type_dir_path, entry)
            if os.path.isfile(path) or os.path.islink(path):
                os.unlink(path)
            elif os.path.isdir(path):
                shutil.rmtree(path)

    return type_dir_path

def main():
    # Check data
    if not os.path.isdir(ALL_PERMISSIONS_DIRECTORY):
        print("The " + ALL_PERMISSIONS_DIRECTORY + " directory is missing.")
        print("Exiting...")
        exit(1)

    if not os.path.isdir(ALL_ROLES_PREPROCESSED_DIRECTORY):
        print("The " + ALL_ROLES_PREPROCESSED_DIRECTORY + " directory is missing.")
        print("Exiting...")
        exit(1)

    data_choice_counter = -1
    data_choice_set = set()
    if not os.path.isdir(REQUESTS_FINAL_DIRECTORY):
        print("The " + REQUESTS_FINAL_DIRECTORY + " directory is missing.")
        print("Exiting...")
        exit(1)
    else:
        # If all dirs exist -> Prompt user which data set shall be used!
        print("Which data set do you want to use?")
        for requests_final in os.listdir(REQUESTS_FINAL_DIRECTORY):
            data_choice_counter += 1
            data_choice_set.add((data_choice_counter, requests_final))
            print("[" + str(data_choice_counter) + "] " + requests_final)

    # Store all valid choices -> 0 - (x-1) if x csv files were found
    valid_choices = {valid_choice for valid_choice, _ in data_choice_set}
    data_choice = input("Input: ")
    try:
        data_choice_int = int(data_choice)
    except ValueError:
        # Choice is not an integer
        print("Invalid choice. Exiting...")
        exit(1)
    if data_choice_int not in valid_choices:
        # Choice is an integer but not in 0 - (x-1)
        print("Invalid choice. Exiting...")
        exit(1)
    else:
        # Found a valid choice -> Extract csv file name into data_choice
        data_choice = next((t for t in data_choice_set if t[0] == data_choice_int), None)
        # The variable data_choice now stores the name of a csv file, e.g. storage.csv !!
        data_choice = data_choice[1]

    print("You chose: " + data_choice)

    options = set()
    perform_b = input("Do you want to run the Baseline experiments? [y/N]").strip().lower()
    if perform_b == "y":
        print("OK")
        options.add(1)

    perform_a = input("Do you want to run the RBAC-Aware experiments? [y/N]").strip().lower()
    if perform_a == "y":
        print("OK")
        options.add(2)

    perform_n = input("Do you want to run the No-LLM experiments? [y/N]").strip().lower()
    if perform_n == "y":
        print("OK")
        options.add(3)

    if len(options) == 0:
        print("You did not chose any experiments. Abort...")
        exit(1)

    # Path to subdirectory for the data_choice
    output_entry_directory = os.path.join(OUTPUT_DIRECTORY, data_choice.split(".")[0])

    ###################### Experiments ########################
    # Load requests
    requests_final_filepath = os.path.join(REQUESTS_FINAL_DIRECTORY, data_choice)
    requests = set()
    with open(requests_final_filepath, newline='', encoding='utf-8') as requests_csv:
        reader = csv.DictReader(requests_csv)
        for row in reader:
            requests.add(row['request'])

    # Load role-to-permission assignments
    pa_filepath = os.path.join(ALL_ROLES_PREPROCESSED_DIRECTORY, data_choice)
    pa: set[tuple[str, str]] = set()
    with open(pa_filepath, newline='', encoding='utf-8') as pa_csv:
        reader = csv.DictReader(pa_csv)
        for row in reader:
            pa.add((
                row["role_name"],
                row["permission_name"]
            ))

    # Save original rbac model
    original_pa = set(pa)

    if 1 in options:
        # Create subdirectory for baseline experiments
        experiment_type_directory = create_type_subdirectory(output_entry_directory, "baseline")
        # Init log writer
        log_path = os.path.join(experiment_type_directory, "watsonx_runner_information.txt")
        log_writer = open(log_path, "w")
        print("Starting Baseline Experiments.")
        log_writer.write("Starting Baseline Experiments.\n")
        # Information later added into system prompts
        category_name = data_choice.split(".")[0]
        print("Category name: " + category_name)
        log_writer.write("Category name: " + category_name + "\n")
        explicit_permission_1, explicit_permission_2 = get_permission_examples(data_choice)
        print("Explicit example 1: " + explicit_permission_1)
        log_writer.write("Explicit example 1: " + explicit_permission_1 + "\n")
        print("Explicit example 2: " + explicit_permission_2)
        log_writer.write("Explicit example 2: " + explicit_permission_2 + "\n")
        wildcard_permission = get_wildcard_example(data_choice)
        print("Wildcard example: " + wildcard_permission)
        log_writer.write("Wildcard example: " + wildcard_permission + "\n")
        role_1, role_2 = get_role_examples(data_choice.split(".")[0])
        print("Role example 1: " + role_1)
        print("Role example 2: " + role_2)
        log_writer.write("Role example 1: " + role_1 + "\n")
        log_writer.write("Role example 2: " + role_2 + "\n")
        invalid_roles = get_invalid_roles(data_choice.split(".")[0])
        invalid_roles = "\n".join(invalid_roles)
        print("Invalid roles:\n" + invalid_roles)
        log_writer.write("Invalid roles:\n" + invalid_roles + "\n")

        # For each used model id
        for model_id in MODELS:
            print("Using model: " + model_id)
            log_writer.write("Using model: " + model_id + "\n")
            model = ModelInference(
                model_id=model_id,
                params={
                    # https://ibm.github.io/watsonx-ai-python-sdk/v1.4.2/fm_schema.html#ibm_watsonx_ai.foundation_models.schema.TextGenParameters
                    "decoding_method": "greedy",
                    "max_new_tokens": 100,
                    "temperature": 0.0
                },
                credentials=CREDENTIALS,
                project_id=PROJECT_ID
            )
            # Create csv file and open it
            safe_model_id = model_id.replace("/", "_")
            csv_path = os.path.join(experiment_type_directory, "B_" + safe_model_id + ".csv")
            with open(csv_path, "a", newline="", encoding="utf-8") as output_csv:
                writer = csv.writer(output_csv, delimiter=";")
                writer.writerow(["request", "permission", "role"])

                # Traverse requests
                for request in requests:
                    n = 0
                    # Send each request N_MAX times
                    while n < N_MAX:
                        # Get permission
                        permission_result = get_permission_from_plain_text_model(model, request, category_name,
                                                                                 explicit_permission_1, explicit_permission_2,
                                                                                 wildcard_permission)
                        # In the next prompt, tell the LLM what it previously translated the request to, unless it was none
                        if permission_result == "none":
                            request_n = request
                        else:
                            request_n = request + " Required permission: " + permission_result
                        # Get role
                        role_result = get_role_from_plain_text_model(model, request_n, category_name, role_1,
                                                                     role_2, invalid_roles)
                        writer.writerow([request, permission_result, role_result])
                        n += 1
        log_writer.close()

    if 2 in options:
        # Create subdirectory for RBAC-Aware experiments
        experiment_type_directory = create_type_subdirectory(output_entry_directory, "rbac-aware")
        # Init log writer
        log_path = os.path.join(experiment_type_directory, "watsonx_runner_information.txt")
        log_writer = open(log_path, "w")
        print("Starting RBAC-Aware experiments.")
        log_writer.write("Starting RBAC-Aware experiments.\n")
        print("Using embedding model: " + GRANITE_EMBEDDING_ID)
        log_writer.write("Using embedding model: " + GRANITE_EMBEDDING_ID + "\n")
        embedding_model = Embeddings(model_id=GRANITE_EMBEDDING_ID, credentials=CREDENTIALS, project_id=PROJECT_ID)

        # For each target % assigned roles
        for perc_assigned_entry in PERC_ASSIGNED_ROLES:
            print("Target % assigned roles: " + str(perc_assigned_entry))
            log_writer.write("Target % assigned roles: " + str(perc_assigned_entry) + "\n")

            # For each used model id
            for model_id in MODELS:
                print("Using model: " + model_id)
                log_writer.write("Using model:" + model_id + "\n")
                model = ModelInference(
                    model_id=model_id,
                    params={
                        # https://ibm.github.io/watsonx-ai-python-sdk/v1.4.2/fm_schema.html#ibm_watsonx_ai.foundation_models.schema.TextGenParameters
                        "decoding_method": "greedy",
                        "max_new_tokens": 100,
                        "temperature": 0.0
                    },
                    credentials=CREDENTIALS,
                    project_id=PROJECT_ID
                )

                # For each target number shown permissions
                for num_permissions_entry in NUM_PERMISSIONS:
                    print("Target number shown permissions: " + str(num_permissions_entry))
                    log_writer.write("Target number shown permissions: " + str(num_permissions_entry) + "\n")

                    # Lists for storing the role solutions in this permission setup
                    llm_list = []
                    algo_list = []
                    # Create csv file and init it
                    safe_model_id = model_id.replace("/", "_")
                    csv_path_llm = os.path.join(experiment_type_directory,
                                               "A_" + safe_model_id + "_" + str(perc_assigned_entry) + "%Ra_" + str(
                                                   num_permissions_entry) + "P_llmR.csv")
                    csv_path_alg = os.path.join(experiment_type_directory,
                                               "A_" + safe_model_id + "_" + str(perc_assigned_entry) + "%Ra_" + str(
                                                   num_permissions_entry) + "P_algR.csv")
                    with open(csv_path_llm, "a", newline="", encoding="utf-8") as output_csv:
                        writer = csv.writer(output_csv, delimiter=";")
                        writer.writerow(["request", "permission", "role"])
                    with open(csv_path_alg, "a", newline="", encoding="utf-8") as output_csv:
                        writer = csv.writer(output_csv, delimiter=";")
                        writer.writerow(["request", "permission", "role"])

                    # Traverse requests
                    for request in requests:
                        # Get solution of request
                        solution = ""
                        with open(requests_final_filepath, newline='', encoding='utf-8') as requests_csv:
                            reader = csv.DictReader(requests_csv)
                            for row in reader:
                                if row['request'] == request:
                                    solution = row['permission_name']
                        if solution == "":
                            print("No solution was found for request: " + request + " in category: " + data_choice)
                            exit(1)

                        # Calculate new RBAC model based on the perc_assigned_entry value
                        pa, assigned_explicits = orgmodel_calculator(solution, original_pa, perc_assigned_entry)
                        # Unique set of lowercased permissions contained in the new PA relation
                        permissions = {item[1] for item in pa}

                        # Get permission embeddings
                        inputs = list(permissions) + [request]
                        embeddings = embedding_model.embed_documents(inputs)
                        # Split permission embeddings
                        # All expect the last (permissions)
                        permission_embeddings = embeddings[:-1]
                        # Only the last (request)
                        request_embedding = embeddings[-1]
                        # Compute cosine similarity
                        # Each entry is the similarity between the request and a permission
                        similarities = cosine_similarity([request_embedding], permission_embeddings)[0]

                        # If number of permissions = nop < k -> Then only insert nop permissions
                        if len(permissions) < num_permissions_entry:
                            num_permissions_entry = len(permissions)

                        n = 0
                        # Send each request N_MAX times
                        while n < N_MAX:
                            # Sort and take best :num_permissions_entry permissions
                            top_indices = np.argsort(similarities)[::-1][:num_permissions_entry]
                            system_prompt_permissions = "\n".join(list(permissions)[i] for i in top_indices)
                            # Get permission
                            permission_result = get_permission_from_aware_model(model, request, system_prompt_permissions)

                            # If there is no perm. translation, we generate 5 similar roles to the request
                            if permission_result == "none":
                                # Calculate the similarity between a request and a role
                                role_scores = []  # list of tuples (role_name, avg_similarity)
                                roles = {item[0] for item in pa}  # Set of roles contained in the given PA relation
                                for role in roles:
                                    # For each role, calculate the similarities between each permission and the request
                                    role_permission_sims = []
                                    for role_name, permission_name in pa:
                                        if role_name == role:
                                            # Get index of current permission
                                            idx = list(permissions).index(permission_name)
                                            # Get the similarity of this permission, and add it to the role_permission_sims
                                            role_permission_sims.append(similarities[idx])

                                    # Calculate the avg. permission similarity of this role
                                    avg_sim = sum(role_permission_sims) / len(role_permission_sims)
                                    # Add this final value to the role_scores tuples
                                    role_scores.append((role, avg_sim))

                                # x[1] -> Sort according to second element, reverse=True -> Descending order
                                role_scores.sort(key=lambda x: x[1], reverse=True)
                                # Check if five roles really exist. If less -> Insert all available roles.
                                num_roles_entry = 5
                                if len(role_scores) < 5:
                                    num_roles_entry = len(role_scores)
                                top_roles = [r for (r, score) in role_scores[:num_roles_entry]]
                                # Top roles are candidate roles
                                role_result = get_role_from_aware_model(model, request, pa, top_roles, assigned_explicits)
                            # permission_result is not none -> There was some permission result
                            else:
                                # In the next prompt, tell the LLM what it previously translated the request to
                                request_n = request + " Required permission: " + permission_result
                                # Calculate the candidate roles -> All roles that contain the permission_result
                                # or a wildcard that contains the permission_result
                                candidate_roles = set()
                                roles = {item[0] for item in pa} # Set of roles contained in the given PA relation
                                for role in roles:
                                    add_role_as_candidate = False
                                    for role_name, permission_name in pa:
                                        if role_name == role:
                                            # Role directly contains the permission_result -> Add as CR
                                            if permission_name == permission_result:
                                                add_role_as_candidate = True
                                            else:
                                                # Role contains a wildcard permission
                                                if "*" in permission_name:
                                                    # ... and this wildcard permission matches the permission_result -> Add as CR
                                                    if fnmatch(permission_result, permission_name):
                                                        add_role_as_candidate = True
                                    if add_role_as_candidate:
                                        candidate_roles.add(role)

                                role_result = get_role_from_aware_model(model, request_n, pa, list(candidate_roles), assigned_explicits)

                            # Write result line into list
                            llm_list.append([request,permission_result,role_result])
                            # Get role with algorithm
                            role_result = find_role(permission_result, original_pa, pa, assigned_explicits)
                            # Write result line into list
                            algo_list.append([request, permission_result, role_result])
                            n += 1

                    # Copy llm_list and algo_list into csv files
                    with open(csv_path_llm, "a", newline="", encoding="utf-8") as output_csv:
                        writer = csv.writer(output_csv, delimiter=";")
                        for row in llm_list:
                            writer.writerow(row)
                    with open(csv_path_alg, "a", newline="", encoding="utf-8") as output_csv:
                        writer = csv.writer(output_csv, delimiter=";")
                        for row in algo_list:
                            writer.writerow(row)
        log_writer.close()

    if 3 in options:
        # Create subdirectory for No-LLM experiments
        experiment_type_directory = create_type_subdirectory(output_entry_directory, "no-llm")
        # Init log writer
        log_path = os.path.join(experiment_type_directory, "watsonx_runner_information.txt")
        log_writer = open(log_path, "w")
        print("Starting No-LLM experiments.")
        embedding_model = Embeddings(model_id=GRANITE_EMBEDDING_ID, credentials=CREDENTIALS, project_id=PROJECT_ID)
        print("Using embedding model: " + GRANITE_EMBEDDING_ID)
        log_writer.write("Using embedding model: " + GRANITE_EMBEDDING_ID + "\n")

        # For each target % assigned roles
        for perc_assigned_entry in PERC_ASSIGNED_ROLES:
            print("Target % assigned roles: " + str(perc_assigned_entry))
            log_writer.write("Target % assigned roles: " + str(perc_assigned_entry) + "\n")
            # Create csv file and open it
            safe_model_id = GRANITE_EMBEDDING_ID.replace("/", "_")
            csv_path = os.path.join(experiment_type_directory, "N_" + safe_model_id + "_" + str(perc_assigned_entry) + "%Ra.csv")
            with open(csv_path, "a", newline="", encoding="utf-8") as output_csv:
                writer = csv.writer(output_csv, delimiter=";")
                writer.writerow(["request", "permission", "role"])

                # Traverse requests
                for request in requests:
                    # Get solution of request
                    solution = ""
                    with open(requests_final_filepath, newline='', encoding='utf-8') as requests_csv:
                        reader = csv.DictReader(requests_csv)
                        for row in reader:
                            if row['request'] == request:
                                solution = row['permission_name']
                    if solution == "":
                        print("No solution was found for request: " + request + " in category: " + data_choice)
                        exit(1)

                    # Calculate new RBAC model based on the perc_assigned_entry value
                    pa, assigned_explicits = orgmodel_calculator(solution, original_pa, perc_assigned_entry)
                    # Unique set of lowercased permissions contained in the new PA relation
                    permissions = {item[1] for item in pa}

                    # Get permission embeddings
                    inputs = list(permissions) + [request]
                    embeddings = embedding_model.embed_documents(inputs)
                    # Split permission embeddings
                    # All expect the last (permissions)
                    permission_embeddings = embeddings[:-1]
                    # Only the last (request)
                    request_embedding = embeddings[-1]
                    # Compute cosine similarity
                    # Each entry is the similarity between the request and a permission
                    similarities = cosine_similarity([request_embedding], permission_embeddings)[0]

                    n = 0
                    # Send each request N_MAX times
                    while n < N_MAX:
                        # Get permission
                        top_index = np.argmax(similarities)
                        # permission_result is always lowercase and stripped, as all permissions are
                        permission_result = list(permissions)[top_index]
                        # Get role
                        role_result = find_role(permission_result, original_pa, pa, assigned_explicits)
                        writer.writerow([request, permission_result, role_result])
                        n += 1
        log_writer.close()

if __name__ == "__main__":
    main()