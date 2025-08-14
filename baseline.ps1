$baseline = @"
apiVersion: github.com/microsoft/PSRule/v1
kind: Baseline
metadata:
  name: essential8-ml2
spec:
  rule:
    tag:
      e8: /.*/
      maturity: /ML2/
  include:
    - ./rules
"@

# choose ONE of these paths based on where you keep the baseline:

$path = ".\baselines\essential8.baseline.yaml"   # or in .\baselines

Set-Content -Path $path -Value $baseline -Encoding utf8
