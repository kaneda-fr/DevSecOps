package logicapp.security

# Ensure the input is a Logic App workflow definition
is_logic_app_workflow {
    input.kind == "Stateful"
    input.definition != null
}

# Check if the secureData properties for both inputs and outputs are present and configured correctly.
is_secure(resource) {
    resource.runtimeConfiguration.secureData.properties[_] == "inputs"
    resource.runtimeConfiguration.secureData.properties[_] == "outputs"
}

# Recursively check all actions, including nested actions within control structures like If, ForEach, etc.
all_secure(items, non_compliant) {
    not some item_name, item in items {
        not secure_check_recursive(item_name, item, non_compliant)
    }
}

# Function to recursively check actions, accounting for nesting and control structures.
secure_check_recursive(name, action, non_compliant) {
    is_secure(action)
} {
    action.type == "If"
    all_secure(action.actions, non_compliant)
    all_secure(action.else.actions, non_compliant)
} {
    action.type == "Foreach"
    all_secure(action.actions, non_compliant)
} {
    action.type == "Until"
    all_secure(action.actions, non_compliant)
} {
    action.type == "Switch"
    secure_branches(action.cases, non_compliant)
}

# Helper function to check all branches in a Switch case.
secure_branches(cases, non_compliant) {
    not some case_name, case in cases {
        not all_secure(case.actions, non_compliant)
    }
}

# Collect non-compliant actions or triggers
collect_non_compliant(name, resource, non_compliant) {
    not is_secure(resource)
    non_compliant[name] = resource
}

# Main compliance check, ensuring it only applies to Logic App workflows
compliant[non_compliant] {
    is_logic_app_workflow
    workflow := input.definition

    non_compliant := {}

    all_secure(workflow.triggers, non_compliant)
    all_secure(workflow.actions, non_compliant)

    count(non_compliant) == 0
}

# Violation message if any actions or triggers are not compliant, including their names.
violation[msg] {
    not compliant[non_compliant]
    non_compliant_list := [name | name in keys(non_compliant)]
    msg := sprintf("The following triggers or actions are missing secured inputs or outputs: %v", [non_compliant_list])
}

/* 
    OPA Policy for auditing secure inputs and outputs in Azure Logic Apps
    - Ensures that the policy only applies to Logic App workflows
    - Recursively checks all triggers and actions, including nested structures
    - Collects the names of non-compliant actions or triggers
    - Outputs the names of non-compliant actions or triggers in the violation message

    Author: Sebastien Lacoste-seris
    Copyright (c) 2024 Sebastien Lacoste-seris. All rights reserved.
*/
