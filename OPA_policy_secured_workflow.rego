package logicapp.security

# Check if the secureData properties for inputs and outputs are present and configured correctly.
is_secure(resource) {
    resource.runtimeConfiguration.secureData.properties[_] == "inputs"
    resource.runtimeConfiguration.secureData.properties[_] == "outputs"
}

# Recursively check all actions, including nested actions within control structures like If, ForEach, etc.
all_secure(items) {
    not some item in items {
        not secure_check_recursive(item)
    }
}

# Function to recursively check actions, accounting for nesting and control structures.
secure_check_recursive(action) {
    is_secure(action)
}

secure_check_recursive(action) {
    action.type == "If"
    all_secure(action.actions)
    all_secure(action.else.actions)
}

secure_check_recursive(action) {
    action.type == "Foreach"
    all_secure(action.actions)
}

secure_check_recursive(action) {
    action.type == "Until"
    all_secure(action.actions)
}

secure_check_recursive(action) {
    action.type == "Switch"
    all secure_branches(action.cases)
}

# Helper function to check all branches in a Switch case.
secure_branches(cases) {
    not some case in cases {
        not all_secure(case.actions)
    }
}

# Check for compliance in both triggers and actions.
compliant {
    workflow := input.definition
    all_secure(workflow.triggers)
    all_secure(workflow.actions)
}

# Violation message if any actions or triggers are not compliant.
violation[msg] {
    not compliant
    msg := "Some triggers or actions in the Logic App workflow are missing secured inputs or outputs."
}
