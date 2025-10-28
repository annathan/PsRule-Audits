# FixedAdvancedEvaluator.ps1
# Fixed advanced rule evaluation engine

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$InputJsonPath,
    
    [Parameter(Mandatory = $true)]
    [string]$RulesJsonPath,
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = ".\advanced-evaluation-results.json",
    
    [Parameter(Mandatory = $false)]
    [switch]$Parallel
)

Write-Host "🔍 Starting fixed advanced rule evaluation..." -ForegroundColor Cyan

# Load input data
$InputData = Get-Content $InputJsonPath | ConvertFrom-Json
Write-Host "  📊 Loaded input data with $($InputData.Count) records" -ForegroundColor Gray

# Load rules
$Rules = Get-Content $RulesJsonPath | ConvertFrom-Json
Write-Host "  📋 Loaded $($Rules.Count) advanced rules" -ForegroundColor Gray

# Enhanced JSON path resolution
function Get-JsonPathValue {
    param(
        [object]$Data,
        [string]$Path
    )
    
    try {
        if ($Path -eq "$") {
            return $Data
        }
        
        # Remove leading $.
        $Path = $Path -replace '^\$\.', ''
        
        # Handle complex nested array access
        if ($Path -match '^(.+)\[(\d+)\]\.(.+)$') {
            $ParentPath = $matches[1]
            $Index = [int]$matches[2]
            $RemainingPath = $matches[3]
            
            $ParentValue = Get-JsonPathValue -Data $Data -Path $ParentPath
            if ($ParentValue -is [array] -and $ParentValue.Count -gt $Index) {
                return Get-JsonPathValue -Data $ParentValue[$Index] -Path $RemainingPath
            }
            return $null
        }
        
        # Handle simple array indexing
        if ($Path -match '^(.+)\[(\d+)\]$') {
            $ParentPath = $matches[1]
            $Index = [int]$matches[2]
            $ParentValue = Get-JsonPathValue -Data $Data -Path $ParentPath
            if ($ParentValue -is [array] -and $ParentValue.Count -gt $Index) {
                return $ParentValue[$Index]
            }
            return $null
        }
        
        if ($Path -match '^(.+)\[\*\]\.(.+)$') {
            $ParentPath = $matches[1]
            $PropertyName = $matches[2]
            $ParentValue = Get-JsonPathValue -Data $Data -Path $ParentPath
            if ($ParentValue -is [array]) {
                return $ParentValue | ForEach-Object { Get-JsonPathValue -Data $_ -Path $PropertyName }
            }
            return $null
        }
        
        # Handle simple property access
        $CurrentValue = $Data
        $PathParts = $Path -split '\.'
        
        foreach ($Part in $PathParts) {
            if ($CurrentValue -is [PSCustomObject] -and $CurrentValue.PSObject.Properties.Name -contains $Part) {
                $CurrentValue = $CurrentValue.$Part
            } else {
                return $null
            }
        }
        
        return $CurrentValue
    } catch {
        return $null
    }
}

# Fixed evaluator with proper regex handling
function Test-Evaluator {
    param(
        [object]$Value,
        [string]$Evaluator,
        [object]$ExpectedValue,
        [string]$ExpectedType,
        [string]$CustomEvaluator
    )
    
    # Handle custom evaluator
    if ($CustomEvaluator) {
        try {
            $ExecutionContext = [System.Management.Automation.PowerShell]::Create()
            $ExecutionContext.AddScript($CustomEvaluator)
            $ExecutionContext.AddParameter('_', $Value)
            
            $Result = $ExecutionContext.Invoke()
            $ExecutionContext.Dispose()
            
            return @{
                Result = if ($Result -is [bool]) { $Result } else { $Result -ne $null -and $Result -ne $false -and $Result -ne 0 }
                Evidence = "Custom evaluator: $CustomEvaluator, result: $($Result | ConvertTo-Json -Compress)"
            }
        } catch {
            return @{
                Result = $false
                Evidence = "Custom evaluator error: $($_.Exception.Message)"
            }
        }
    }
    
    # Type check first
    if ($ExpectedType -and $Value -ne $null) {
        $ActualType = if ($Value -is [array]) { "array" } 
                     elseif ($Value -is [PSCustomObject]) { "object" } 
                     elseif ($Value -is [string]) { "string" }
                     elseif ($Value -is [bool]) { "boolean" }
                     elseif ($Value -is [int] -or $Value -is [double] -or $Value -is [decimal]) { "number" }
                     else { "unknown" }
        
        if ($ActualType -ne $ExpectedType) {
            return @{
                Result = $false
                Evidence = "Type mismatch: expected '$ExpectedType', got '$ActualType'"
            }
        }
    }
    
    # Apply evaluator with fixed regex handling
    switch ($Evaluator) {
        "exists" {
            return @{
                Result = ($Value -ne $null -and $Value -ne "")
                Evidence = if ($Value -ne $null) { "Value exists: $($Value | ConvertTo-Json -Compress)" } else { "Value does not exist" }
            }
        }
        "type" {
            $ActualType = if ($Value -is [array]) { "array" } 
                         elseif ($Value -is [PSCustomObject]) { "object" } 
                         else { "unknown" }
            return @{
                Result = ($ActualType -eq $ExpectedType)
                Evidence = "Type check: expected '$ExpectedType', got '$ActualType'"
            }
        }
        "equals" {
            return @{
                Result = ($Value -eq $ExpectedValue)
                Evidence = "Value comparison: expected '$ExpectedValue', got '$($Value | ConvertTo-Json -Compress)'"
            }
        }
        "contains" {
            if ($Value -is [array]) {
                $ContainsValue = $Value -contains $ExpectedValue
                return @{
                    Result = $ContainsValue
                    Evidence = "Array contains check: looking for '$ExpectedValue' in $($Value | ConvertTo-Json -Compress)"
                }
            } elseif ($Value -is [string]) {
                $ContainsValue = $Value -like "*$ExpectedValue*"
                return @{
                    Result = $ContainsValue
                    Evidence = "String contains check: looking for '$ExpectedValue' in '$Value'"
                }
            } else {
                return @{
                    Result = $false
                    Evidence = "Contains check failed: value is not array or string"
                }
            }
        }
        { $_ -match '^arrayLength>=(\d+)$' } {
            if ($matches -and $matches.Count -gt 1) {
                $MinLength = [int]$matches[1]
                if ($Value -is [array]) {
                    $Result = $Value.Count -ge $MinLength
                    return @{
                        Result = $Result
                        Evidence = "Array length check: expected >= $MinLength, got $($Value.Count)"
                    }
                } else {
                    return @{
                        Result = $false
                        Evidence = "Array length check failed: value is not an array"
                    }
                }
            } else {
                return @{
                    Result = $false
                    Evidence = "Invalid arrayLength evaluator format: $Evaluator"
                }
            }
        }
        { $_ -match '^arrayLength<=(\d+)$' } {
            if ($matches -and $matches.Count -gt 1) {
                $MaxLength = [int]$matches[1]
                if ($Value -is [array]) {
                    $Result = $Value.Count -le $MaxLength
                    return @{
                        Result = $Result
                        Evidence = "Array length check: expected <= $MaxLength, got $($Value.Count)"
                    }
                } else {
                    return @{
                        Result = $false
                        Evidence = "Array length check failed: value is not an array"
                    }
                }
            } else {
                return @{
                    Result = $false
                    Evidence = "Invalid arrayLength evaluator format: $Evaluator"
                }
            }
        }
        default {
            return @{
                Result = $false
                Evidence = "Unknown evaluator: $Evaluator"
            }
        }
    }
}

# Evaluate composite conditions
function Test-CompositeRule {
    param(
        [object]$Data,
        [object]$Rule
    )
    
    $Results = @()
    $AllPassed = $true
    
    foreach ($Condition in $Rule.conditions) {
        $TargetValue = Get-JsonPathValue -Data $Data -Path $Condition.targetPath
        $Evaluation = Test-Evaluator -Value $TargetValue -Evaluator $Condition.evaluator -ExpectedValue $Condition.expectedValue -ExpectedType $Condition.expectedType
        
        $Results += @{
            Condition = $Condition
            Result = $Evaluation.Result
            Evidence = $Evaluation.Evidence
        }
        
        if ($Rule.logic -eq "AND" -and -not $Evaluation.Result) {
            $AllPassed = $false
        } elseif ($Rule.logic -eq "OR" -and $Evaluation.Result) {
            $AllPassed = $true
            break
        }
    }
    
    return @{
        Result = $AllPassed
        Evidence = "Composite $($Rule.logic) evaluation: $($Results | ForEach-Object { "$($_.Condition.targetPath): $($_.Result)" }) -join ', '"
        ConditionResults = $Results
    }
}

# Check rule dependencies
function Test-RuleDependencies {
    param(
        [string[]]$Dependencies,
        [hashtable]$RuleResults
    )
    
    foreach ($Dependency in $Dependencies) {
        if (-not $RuleResults.ContainsKey($Dependency) -or $RuleResults[$Dependency].Status -ne "passed") {
            return $false
        }
    }
    return $true
}

# Process rules with dependency resolution
function Process-Rules {
    param(
        [object]$Data,
        [object[]]$Rules
    )
    
    $RuleResults = @{}
    $AllFindings = @()
    
    # Process rules in order (simple dependency handling)
    foreach ($Rule in $Rules) {
        # Check if dependencies are satisfied
        if ($Rule.dependsOn -and -not (Test-RuleDependencies -Dependencies $Rule.dependsOn -RuleResults $RuleResults)) {
            $Finding = @{
                title = $Rule.title
                whyItMatters = $Rule.whyItMatters
                evidence = "Dependency not satisfied: $($Rule.dependsOn -join ', ')"
                remediation = $Rule.remediation
                status = "warning"
                severity = $Rule.severity
                ruleId = $Rule.id
                targetPath = if ($Rule.targetPath) { $Rule.targetPath } else { "N/A" }
                evaluationResult = "Rule skipped due to failed dependencies"
            }
            $AllFindings += $Finding
            $RuleResults[$Rule.id] = @{ Status = "warning" }
            continue
        }
        
        # Evaluate the rule
        if ($Rule.logic -and $Rule.conditions) {
            # Composite rule
            $Evaluation = Test-CompositeRule -Data $Data -Rule $Rule
            $TargetValue = Get-JsonPathValue -Data $Data -Path $Rule.evidencePath
        } else {
            # Simple rule
            $TargetValue = Get-JsonPathValue -Data $Data -Path $Rule.targetPath
            $Evaluation = Test-Evaluator -Value $TargetValue -Evaluator $Rule.evaluator -ExpectedValue $Rule.expectedValue -ExpectedType $Rule.expectedType -CustomEvaluator $Rule.customEvaluator
        }
        
        # Get evidence
        $EvidenceValue = Get-JsonPathValue -Data $Data -Path $Rule.evidencePath
        $EvidenceString = if ($EvidenceValue -ne $null) { 
            $EvidenceValue | ConvertTo-Json -Compress -Depth 3
        } else { 
            "Path not found: $($Rule.evidencePath)" 
        }
        
        # Determine status
        $Status = if ($Evaluation.Result) { "passed" } else { "failed" }
        if ($TargetValue -eq $null -and $Rule.evaluator -ne "exists" -and -not $Rule.customEvaluator) {
            $Status = "warning"
        }
        
        # Create finding
        $Finding = @{
            title = $Rule.title
            whyItMatters = $Rule.whyItMatters
            evidence = $EvidenceString
            remediation = $Rule.remediation
            status = $Status
            severity = $Rule.severity
            ruleId = $Rule.id
            targetPath = if ($Rule.targetPath) { $Rule.targetPath } else { "Composite rule" }
            evaluationResult = $Evaluation.Evidence
        }
        
        $AllFindings += $Finding
        $RuleResults[$Rule.id] = @{ Status = $Status }
    }
    
    return $AllFindings
}

# Process each input record
$AllFindings = @()
$TotalChecks = 0
$PassedCount = 0
$FailedCount = 0
$WarningCount = 0

foreach ($Record in $InputData) {
    Write-Host "  🔍 Processing record: $($Record.UserPrincipalName)" -ForegroundColor Gray
    
    $RecordFindings = Process-Rules -Data $Record -Rules $Rules
    $AllFindings += $RecordFindings
    $TotalChecks += $RecordFindings.Count
    
    foreach ($Finding in $RecordFindings) {
        switch ($Finding.status) {
            "passed" { $PassedCount++ }
            "failed" { $FailedCount++ }
            "warning" { $WarningCount++ }
        }
    }
}

# Create output structure with controlled depth
$Output = @{
    report = @{
        generatedAt = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
        source = "Essential 8 Advanced Compliance Assessment"
        inputRecords = $InputData.Count
        rulesEvaluated = $Rules.Count
        parallelProcessing = $Parallel
    }
    summary = @{
        totalChecks = $TotalChecks
        passed = $PassedCount
        failed = $FailedCount
        warning = $WarningCount
        complianceScore = if ($TotalChecks -gt 0) { [Math]::Round(($PassedCount / $TotalChecks) * 100, 1) } else { 0 }
    }
    findings = $AllFindings
}

# Save output with controlled depth
$Output | ConvertTo-Json -Depth 5 | Out-File -FilePath $OutputPath -Encoding UTF8

Write-Host ""
Write-Host "📊 Fixed Advanced Evaluation Complete!" -ForegroundColor Green
Write-Host "  Total Checks: $TotalChecks" -ForegroundColor Gray
Write-Host "  Passed: $PassedCount" -ForegroundColor Green
Write-Host "  Failed: $FailedCount" -ForegroundColor Red
Write-Host "  Warnings: $WarningCount" -ForegroundColor Yellow
Write-Host "  Compliance Score: $($Output.summary.complianceScore)%" -ForegroundColor Cyan
Write-Host ""
Write-Host "📄 Results saved to: $OutputPath" -ForegroundColor Gray

return $Output
