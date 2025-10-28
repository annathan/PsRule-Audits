# FixedRuleEvaluator.ps1
# Fixed explicit rule evaluation engine

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$InputJsonPath,
    
    [Parameter(Mandatory = $true)]
    [string]$RulesJsonPath,
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = ".\evaluation-results.json"
)

Write-Host "🔍 Starting fixed rule evaluation..." -ForegroundColor Cyan

# Load input data
$InputData = Get-Content $InputJsonPath | ConvertFrom-Json
Write-Host "  📊 Loaded input data with $($InputData.Count) records" -ForegroundColor Gray

# Load rules
$Rules = Get-Content $RulesJsonPath | ConvertFrom-Json
Write-Host "  📋 Loaded $($Rules.Count) explicit rules" -ForegroundColor Gray

# Evaluation functions
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
        
        # Handle array indexing like [0] or [*]
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
                return $ParentValue | ForEach-Object { $_.$PropertyName }
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

function Test-Evaluator {
    param(
        [object]$Value,
        [string]$Evaluator,
        [object]$ExpectedValue,
        [string]$ExpectedType
    )
    
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
    
    # Apply evaluator
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
        }
        { $_ -match '^arrayLength<=(\d+)$' } {
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
        }
        default {
            return @{
                Result = $false
                Evidence = "Unknown evaluator: $Evaluator"
            }
        }
    }
}

# Process each input record
$AllFindings = @()
$TotalChecks = 0
$PassedCount = 0
$FailedCount = 0
$WarningCount = 0

foreach ($Record in $InputData) {
    Write-Host "  🔍 Processing record: $($Record.UserPrincipalName)" -ForegroundColor Gray
    
    foreach ($Rule in $Rules) {
        $TotalChecks++
        
        # Get target value
        $TargetValue = Get-JsonPathValue -Data $Record -Path $Rule.targetPath
        
        # Get evidence
        $EvidenceValue = Get-JsonPathValue -Data $Record -Path $Rule.evidencePath
        $EvidenceString = if ($EvidenceValue -ne $null) { 
            $EvidenceValue | ConvertTo-Json -Compress 
        } else { 
            "Path not found: $($Rule.evidencePath)" 
        }
        
        # Evaluate rule
        $Evaluation = Test-Evaluator -Value $TargetValue -Evaluator $Rule.evaluator -ExpectedValue $Rule.expectedValue -ExpectedType $Rule.expectedType
        
        # Determine status
        $Status = if ($Evaluation.Result) { "passed" } else { "failed" }
        if ($TargetValue -eq $null -and $Rule.evaluator -ne "exists") {
            $Status = "warning"
            $WarningCount++
        } elseif ($Status -eq "passed") {
            $PassedCount++
        } else {
            $FailedCount++
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
            targetPath = $Rule.targetPath
            evaluationResult = $Evaluation.Evidence
        }
        
        $AllFindings += $Finding
        
        Write-Host "    ✓ $($Rule.title): $Status" -ForegroundColor $(if ($Status -eq "passed") { "Green" } else { "Red" })
    }
}

# Create output structure
$Output = @{
    report = @{
        generatedAt = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
        source = "Essential 8 Compliance Assessment"
        inputRecords = $InputData.Count
        rulesEvaluated = $Rules.Count
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

# Save output
$Output | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputPath -Encoding UTF8

Write-Host ""
Write-Host "📊 Evaluation Complete!" -ForegroundColor Green
Write-Host "  Total Checks: $TotalChecks" -ForegroundColor Gray
Write-Host "  Passed: $PassedCount" -ForegroundColor Green
Write-Host "  Failed: $FailedCount" -ForegroundColor Red
Write-Host "  Warnings: $WarningCount" -ForegroundColor Yellow
Write-Host "  Compliance Score: $($Output.summary.complianceScore)%" -ForegroundColor Cyan
Write-Host ""
Write-Host "📄 Results saved to: $OutputPath" -ForegroundColor Gray

return $Output
