#########################
# This script requires to have previously run the init_azure.py, the get_all_permissions.py, the get_all_roles.py and the get_requests.py scripts
# This script finalizes the permission requests previously stored in the subdir /requests/requests_proposal
# You are free to discard suggested requests based on the request IDs
# The final requests are stored in the subdir /requests/requests_final
#########################

import csv
from pathlib import Path
import os
import shutil
import stat
import random

# Script is located at <project>/src/init_azure.py -> get <project>
PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Paths to required dirs
ALL_ROLES_DIRECTORY = os.path.join(PROJECT_ROOT, "data", "all_roles")
ALL_PERMISSIONS_DIRECTORY = os.path.join(PROJECT_ROOT, "data", "all_permissions")
REQUESTS_FINAL_DIRECTORY = os.path.join(PROJECT_ROOT, "data", "requests", "requests_final")
REQUESTS_PROPOSAL_DIRECTORY = os.path.join(PROJECT_ROOT, "data", "requests", "requests_proposal")

# Change mode to write if entry cannot be removed by rmtree
def remove_readonly(func, path, exc_info):
    os.chmod(path, stat.S_IWRITE)
    func(path)

def main():
    # Check if required dirs and data exist
    if not os.path.isdir(ALL_ROLES_DIRECTORY):
        print("The " + ALL_ROLES_DIRECTORY + " directory is missing.")
        print("Exiting...")
        exit(1)

    if not os.path.isdir(ALL_PERMISSIONS_DIRECTORY):
        print("The " + ALL_PERMISSIONS_DIRECTORY + " directory is missing.")
        print("Exiting...")
        exit(1)

    if not os.path.isdir(REQUESTS_FINAL_DIRECTORY):
        print("The " + REQUESTS_FINAL_DIRECTORY + " directory is missing.")
        print("Exiting...")
        exit(1)

    x = 0 # Count number of request proposal categories
    if not os.path.isdir(REQUESTS_PROPOSAL_DIRECTORY):
        print("The " + REQUESTS_PROPOSAL_DIRECTORY + " directory is missing.")
        print("Exiting...")
        exit(1)
    else:
        for requests_proposal in os.listdir(REQUESTS_PROPOSAL_DIRECTORY):
            x += 1
            print("Found request suggestions for: " + requests_proposal)

    # Discard requests
    answer = input(
        f"Do you want to discard requests? [y/N]: "
    ).strip().lower()

    discarded_requests = set()
    if answer == "y":
        answer = input(
            f"Please enter the request IDs to discard in a comma-separated list:"
        ).strip().lower()

        discarded_requests = {
            item.strip()
            for item in answer.split(",")
            if item.strip()  # avoids empty strings
        }

    for discarded_request in discarded_requests:
        try:
            int(discarded_request)
        except ValueError:
            print("There is at least one invalid ID: " + discarded_request)
            exit(1)

    # Traverse the requests_proposal subdirectory
    for requests_proposal in os.listdir(REQUESTS_PROPOSAL_DIRECTORY):
        proposal_path = os.path.join(REQUESTS_PROPOSAL_DIRECTORY, requests_proposal)
        # Rows which are not removed due to manual filtering
        valid_requests = []

        # Open csv file
        with open(proposal_path, mode="r", newline="", encoding="utf-8") as request_proposal_csv:
            reader = csv.DictReader(request_proposal_csv)
            # Traverse the requests_proposal file
            for row in reader:
                row_id = row["id"].strip()
                # Check if id is discarded
                if row_id in discarded_requests:
                    print("Discarding request with id " + row_id + " in category: " + requests_proposal)
                else:
                    valid_requests.append(row)
                    # Example:
                    # [
                    # {'id': '0',
                    # 'permission_name': '[microsoft.network](../permissions/networking.md#microsoftnetwork)/networkinterfaces/read',
                    # 'json_permission_name': 'microsoft.network/networkinterfaces/read',
                    # 'request': 'I need to get a network interface definition.'},
                    # {'id': '1',
                    # 'permission_name': ...
                    # ]

        # Shuffle rows in a random order with a fixed seed
        random_order_deterministic = random.Random(42)
        random_order_deterministic.shuffle(valid_requests)

        # Take 50 or 100 rows
        if len(valid_requests) >= 100:
            rows_to_write = valid_requests[:100]
        elif len(valid_requests) >= 50:
            rows_to_write = valid_requests[:50]
        else:
            print("In category: " + requests_proposal + " the number of generated requests is < 50.")
            exit(1)

        # Write into requests_final without discarded rows (max 100)
        final_path = os.path.join(REQUESTS_FINAL_DIRECTORY, requests_proposal)
        with open(final_path, mode="w", newline="", encoding="utf-8") as request_final_csv:
            writer = csv.writer(request_final_csv)
            # Write header
            writer.writerow(
                ["permission_name", "request"]
            )

            # Write json_permission name and request into permission_name and request columns
            for row in rows_to_write:
                writer.writerow([
                    row["json_permission_name"],
                    row["request"],
                ])

    # This is the end of the pre-processing steps:
    print("You finished all data pre-processing steps.")
    print("You can now remove the azure_rbac subdirectory from your local workspace, if you want to.")

    print("As a next step, we recommend to run watsonx_runner.py")

if __name__ == "__main__":
    main()