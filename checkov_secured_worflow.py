from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.arm.base_resource_check import BaseResourceCheck

class LogicAppSecureDataCheck(BaseResourceCheck):
    def __init__(self):
        # Initialize the check with a name, ID, supported resources, and categories
        name = "Ensure secure inputs and outputs are configured in Azure Logic Apps"
        id = "CUSTOM_AZURE_LOGICAPPS_SECURE_DATA_CHECK"
        supported_resources = ['Microsoft.Logic/workflows']
        categories = [CheckCategories.SECURITY]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        """
        Scans the Logic App workflow configuration for secureData settings.
        Returns:
            - CheckResult.PASSED if all triggers and actions are compliant.
            - CheckResult.FAILED if any trigger or action is non-compliant.
            - CheckResult.UNKNOWN if the resource is not a Logic App workflow.
        """

        # Ensure the resource has a workflow definition
        if 'definition' not in conf:
            return CheckResult.UNKNOWN

        # Apply check only to stateful Logic App workflows
        if conf.get('kind') == "Stateful":
            # Check triggers
            triggers = conf.get('definition', {}).get('triggers', {})
            for trigger_name, trigger in triggers.items():
                if not self._has_secure_data(trigger):
                    self.record_failure(trigger_name)
                    return CheckResult.FAILED

            # Check actions
            actions = conf.get('definition', {}).get('actions', {})
            for action_name, action in actions.items():
                if not self._has_secure_data(action):
                    self.record_failure(action_name)
                    return CheckResult.FAILED
                
                # Check nested actions within control structures
                if 'actions' in action:
                    for nested_action_name, nested_action in action['actions'].items():
                        if not self._has_secure_data(nested_action):
                            self.record_failure(nested_action_name)
                            return CheckResult.FAILED
                if 'else' in action and 'actions' in action['else']:
                    for nested_action_name, nested_action in action['else']['actions'].items():
                        if not self._has_secure_data(nested_action):
                            self.record_failure(nested_action_name)
                            return CheckResult.FAILED
                if 'foreach' in action and 'actions' in action['foreach']:
                    for nested_action_name, nested_action in action['foreach']['actions'].items():
                        if not self._has_secure_data(nested_action):
                            self.record_failure(nested_action_name)
                            return CheckResult.FAILED
                if 'cases' in action:
                    for case_name, case in action['cases'].items():
                        for nested_action_name, nested_action in case['actions'].items():
                            if not self._has_secure_data(nested_action):
                                self.record_failure(nested_action_name)
                                return CheckResult.FAILED

            return CheckResult.PASSED
        return CheckResult.UNKNOWN

    def _has_secure_data(self, resource):
        """
        Helper function to check if both 'inputs' and 'outputs' are secured in the secureData properties.
        """
        secure_data = resource.get('runtimeConfiguration', {}).get('secureData', {}).get('properties', [])
        return 'inputs' in secure_data and 'outputs' in secure_data

    def record_failure(self, name):
        """
        Helper function to log the name of non-compliant triggers or actions.
        """
        print(f"Non-compliant resource: {name}")

check = LogicAppSecureDataCheck()

"""
Checkov Policy for auditing secure inputs and outputs in Azure Logic Apps
- Ensures that the policy only applies to Logic App workflows
- Recursively checks all triggers and actions, including nested structures
- Outputs the names of non-compliant actions or triggers

Author: Sebastien Lacoste-seris
Copyright (c) 2024 Sebastien Lacoste-seris. All rights reserved.
"""
