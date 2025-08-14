$baseline = @'
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
    - ./rules/*.ps1
'@

New-Item -ItemType Directory -Path .\.ps-rule -ErrorAction SilentlyContinue | Out-Null
Set-Content -Path .\.ps-rule\essential8.baseline.yaml -Value $baseline -Encoding utf8
