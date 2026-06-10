# Permission Request Processing: A Comparative 
Repo containing Python scripts, preprocessed data sets, and LLM-generated output for a Journal submission.

## Contents



## Licensing and Attribution

### Microsoft Data

As described in this README file, this repository includes modified content derived from Microsoft documentations.
These modified files **retain their original licenses** and are subject to their respective terms.

Specifically, the data contents of this repository were derived from the [Azure RBAC data](https://github.com/MicrosoftDocs/azure-docs/blob/main/articles/role-based-access-control/), which is provided by Microsoft and licensed under the [Create Commons Attribution 4.0 International (CC BY 4.0)](https://github.com/MicrosoftDocs/azure-docs/blob/main/LICENSE) and the [MIT](https://github.com/MicrosoftDocs/azure-docs/blob/main/LICENSE-CODE) licenses. (You can also check the *LICENSE-azure-docs* and *LICENSE-CODE-azure-docs* files in this repository).

**Modifications have been made.**

© Microsoft Corporation.

### Original Content

All other materials (which is the Python code in /src) are licensed under the MIT license (see *LICENSE* file in this repository).

## Notes

- The permission requests are not actual user queries, but generated prompts based on modified permission descriptions.
- The data sets as well as the code are provided for academic and research purposes only.
- The RBAC models in /data/all_roles/preprocessed_pa do not contain all roles found in the original Azure built-in roles. They only include roles that do not revoke any permissions, which means they do not havy any *notDataActions* or *notActions* entries.
- The Microsoft data was retrieved on April 28, 2026. We will not track or incorporate future updates made to the original data sources.

## Contact

If you have any questions about the publication or the shown material, please contact max.niedermeier@tum.de

## Citation 

Not yet published.
