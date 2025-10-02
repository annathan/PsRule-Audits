# Synopsis: Essential 8 - Basic test rules
# Description: Simple test rules to verify PSRule is working

# Test rule to verify PSRule is working
Rule 'Essential8.Test.Simple' {
    $Assert.Pass()
}

# Simple MFA test rule
Rule 'Essential8.AzureAD.MFA.Test' -Type 'PSObject' -If { 
    $TargetObject.PSObject.Properties.Name -contains 'UserPrincipalName' 
} {
    # This rule will pass if we find any user data
    $Assert.HasField($TargetObject, 'UserPrincipalName')
}