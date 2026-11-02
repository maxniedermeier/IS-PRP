# Permission Request Processing: An Exploration and Comparative Evaluation
Repo containing Python scripts, preprocessed data sets, and LLM-generated output for a Journal submission.

## Code

### /src/init_azure.py

Copies RBAC model of Azure into **PROJECT_ROOT/azure_rbac**. Note that this data was removed from the Repo.

### /src/get_all_permissions.py

Gather permission data in **PROJECT_ROOT/azure_rbac** and put it into **PROJECT_ROOT/data/all_permissions**.

### /src/get_roles.py

Gather role data in **PROJECT_ROOT/azure_rbac** and put it into **PROJECT_ROOT/data/all_roles**.

### /src/get_requests.py

Create requests from request describtions in **PROJECT_ROOT/azure_rbac** and put the request suggestions into **PROJECT_ROOT/data/requests/requests_proposal**. Those requests need to be manually inspected.

### /src/finalize_requests.py

Allows to discard requests from **PROJECT_ROOT/data/requests/requests_proposal**. Stores final requests in **PROJECT_ROOT/data/requests/requests_final**.

### /src/watsonx_runner.py

Starting point for running experiments. In each experiment, we have a PRP system that turns requests into permissions and roles. The output is written to **/data/output/<data_set>/<experiment_type>/**.

### /src/orgmodel_calculator.py

Implements Algorithm 1 in the paper. Called by the watsonx_runner.py script.

### /src/find_role.py

Implements Algorithm 2 in the paper. Called by the watsonx_runner.py script.

### /src/evaluation_runner.py

Runs the evaluation_process.py script.

### /src/evaluation_process.py

Implements the evaluation metrics in the paper. The output is written to **/data/evaluation/evaluation.xlsx**. Called by the evaluation_runner.py script.

## Licensing and Attribution

### Microsoft Data

As described in this README file, this repository includes modified content derived from Microsoft documentations.
These modified files **retain their original licenses** and are subject to their respective terms.

More specifically, as described above, the data contents of this repository were derived from the [Azure RBAC data](https://github.com/MicrosoftDocs/azure-docs/blob/main/articles/role-based-access-control/), which is provided by Microsoft and licensed under the [Create Commons Attribution 4.0 International (CC BY 4.0)](https://github.com/MicrosoftDocs/azure-docs/blob/main/LICENSE) and the [MIT](https://github.com/MicrosoftDocs/azure-docs/blob/main/LICENSE-CODE) licenses. (You can also check the *LICENSE-azure-docs* and *LICENSE-CODE-azure-docs* files in this repository).

**Modifications have been made.**

© Microsoft Corporation.

### Original Content

All other materials are licensed under the MIT license (see *LICENSE* file in this repository).

## Notes

- The permission requests are not actual user queries, but generated prompts based on modified permission descriptions.
- The data sets as well as the code are provided for academic and research purposes only.
- The RBAC models in /data/all_roles/preprocessed_pa do not contain all roles found in the original Azure built-in roles. They only include roles that do not revoke any permissions, which means roles that do not havy any *notDataActions* or *notActions* entries.
- The Microsoft data was retrieved on April 28, 2026. We will not track or incorporate future updates made to the original data sources.

## Contact

If you have any questions about the publication or the shown material, please contact max.niedermeier@tum.de

## Paper 

If interested, you can read [Paper-Link](https://doi.org/10.1016/j.is.2026.102825) for more information.
