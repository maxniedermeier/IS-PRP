#########################
# This script clones the RBAC part of the Microsoft Azure git repository into <project>/azure_rbac
# If already cloned, you are prompted if you would like to delete the old files and again clone the repo.
# The date of cloning the repo is stored in <project>/data/clone_repo_date/clone_repo_date.txt
#########################

import subprocess
import shutil
import sys
from pathlib import Path
import os
from datetime import datetime
import stat

# Microsoft azure git repo
REPO_URL = "https://github.com/MicrosoftDocs/azure-docs.git"
# Required data
SPARSE_PATH = "articles/role-based-access-control"

# Script is located at <project>/src/init_azure.py -> get <project>
PROJECT_ROOT = Path(__file__).resolve().parent.parent
# Store repo under project
DESTINATION = PROJECT_ROOT / "azure_rbac"

def run(cmd, cwd=None):
    subprocess.run(cmd, check=True, cwd=cwd)

# Clone RBAC data of repo
def clone_repo():
    run([
        "git", "clone",
        "--filter=blob:none",
        "--no-checkout",
        REPO_URL,
        str(DESTINATION)
    ])

    # Enable sparse checkout
    run(["git", "sparse-checkout", "init", "--cone"], cwd=DESTINATION)

    # Select only the desired directory
    run(["git", "sparse-checkout", "set", SPARSE_PATH], cwd=DESTINATION)

    # Checkout main branch
    run(["git", "checkout", "main"], cwd=DESTINATION)

# Change mode to write if entry cannot be removed by rmtree
def remove_readonly(func, path, exc_info):
    os.chmod(path, stat.S_IWRITE)
    func(path)

def main():
    if DESTINATION.exists():
        answer = input(
            f"Repository already exists at '{DESTINATION}'. Overwrite? [y/N]: "
        ).strip().lower()

        if answer != "y":
            print("Aborted. Existing repository kept.")
            sys.exit(0)

        print("Removing existing repository...")
        shutil.rmtree(DESTINATION, onerror=remove_readonly)

    # Next, check if clone_repo_date directory exists. If not -> create directory
    clone_repo_date_directory = os.path.join(PROJECT_ROOT, "data", "clone_repo_date")

    if not os.path.isdir(clone_repo_date_directory):
        # Command makedirs would also create data directory if missing
        os.makedirs(clone_repo_date_directory, exist_ok=True)
        print("The /data/clone_repo_date directory was missing, but was now created.")

    else:
        # If existing -> empty clone_repo_date directory
        for entry in os.listdir(clone_repo_date_directory):
            path = os.path.join(clone_repo_date_directory, entry)

            if os.path.isfile(path) or os.path.islink(path):
                os.unlink(path)
            elif os.path.isdir(path):
                shutil.rmtree(path)

    print("Cloning repository (sparse)...")
    # Clone repo
    clone_repo()
    # Create clone_repo_date.txt file and store the day of download in clone_repo_date directory
    clone_repo_date_file = os.path.join(
        clone_repo_date_directory, "clone_repo_date.txt"
    )

    today = datetime.utcnow().strftime("%Y-%m-%d")

    with open(clone_repo_date_file, "w", encoding="utf-8") as f:
        f.write(today + "\n")
    print("Repository cloned successfully.")
    print("As a next step, we recommend to run get_all_permissions.py")

if __name__ == "__main__":
    main()