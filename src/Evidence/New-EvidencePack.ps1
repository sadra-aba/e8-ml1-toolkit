<#
    New-EvidencePack.ps1
    Render a stored assessment run (JSON) into a single self-contained HTML
    evidence pack. NO Microsoft Graph dependency: a pack can be regenerated from
    stored results without re-running the assessment.

    Input JSON shape (produced by Invoke-E8Assessment.ps1):
      {
        "meta":    { studentName, studentId, tenantDomain, assessingAccount,
                     collectedUtc, collectedLocal, detectedTier, securityDefaults,
                     toolkitVersion, mode },
        "results": [ <verdict objects from New-E8Verdict> ],
        "transition": { "before": <verdict>, "after": <verdict> }   # optional
      }
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory, ParameterSetName='Path')] [string] $RunJsonPath,
    [Parameter(Mandatory, ParameterSetName='Object')] $Run,
    [Parameter(Mandatory)] [string] $OutputPath
)

$ErrorActionPreference = 'Stop'

if ($PSCmdlet.ParameterSetName -eq 'Path') {
    if (-not (Test-Path -LiteralPath $RunJsonPath)) { throw "Run JSON not found: $RunJsonPath" }
    $Run = (Get-Content -LiteralPath $RunJsonPath -Raw) | ConvertFrom-Json
}

function HtmlEncode([string]$s) {
    if ($null -eq $s) { return '' }
    return [System.Net.WebUtility]::HtmlEncode($s)
}
function BadgeClass([string]$verdict) {
    switch ($verdict) {
        'Compliant'    { 'v-ok' }
        'Partial'      { 'v-partial' }
        'NonCompliant' { 'v-bad' }
        'Blocked'      { 'v-blocked' }
        default        { 'v-na' }
    }
}

$meta    = $Run.meta
$results = @($Run.results)

# --- summary counts ---
$counts = @{ Compliant=0; Partial=0; NonCompliant=0; Blocked=0; NotAssessed=0 }
foreach ($r in $results) { if ($counts.ContainsKey($r.verdict)) { $counts[$r.verdict]++ } }

$sb = New-Object System.Text.StringBuilder
function Add([string]$t) { [void]$script:sb.AppendLine($t) }

Add '<!doctype html>'
Add '<html lang="en"><head><meta charset="utf-8">'
Add '<meta name="viewport" content="width=device-width, initial-scale=1">'
Add ("<title>Essential Eight ML1 Evidence Pack - {0}</title>" -f (HtmlEncode $meta.tenantDomain))
Add @'
<style>
  :root { --bg:#ffffff; --fg:#1b1f24; --muted:#5b6670; --line:#e2e6ea; --card:#f6f8fa;
          --ok:#1a7f37; --okbg:#e6f4ea; --partial:#9a6700; --partialbg:#fff4e0;
          --bad:#b42318; --badbg:#fde8e6; --blocked:#53389e; --blockedbg:#efe9fb;
          --na:#57606a; --nabg:#eef1f4; }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--bg); color:var(--fg);
         font:15px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif; }
  .wrap { max-width:960px; margin:0 auto; padding:32px 20px 64px; }
  h1 { font-size:24px; margin:0 0 4px; }
  h2 { font-size:18px; margin:32px 0 12px; border-bottom:1px solid var(--line); padding-bottom:6px; }
  .sub { color:var(--muted); font-size:13px; }
  .meta { background:var(--card); border:1px solid var(--line); border-radius:10px;
          padding:16px 20px; margin:20px 0; display:grid; grid-template-columns:1fr 1fr; gap:6px 24px; }
  .meta div { font-size:13px; } .meta b { color:var(--muted); font-weight:600; }
  table { width:100%; border-collapse:collapse; margin:8px 0; }
  th,td { text-align:left; padding:9px 10px; border-bottom:1px solid var(--line); font-size:14px; vertical-align:top; }
  th { color:var(--muted); font-weight:600; font-size:12px; text-transform:uppercase; letter-spacing:.03em; }
  .badge { display:inline-block; padding:2px 10px; border-radius:999px; font-size:12px; font-weight:600; white-space:nowrap; }
  .v-ok{color:var(--ok);background:var(--okbg);} .v-partial{color:var(--partial);background:var(--partialbg);}
  .v-bad{color:var(--bad);background:var(--badbg);} .v-blocked{color:var(--blocked);background:var(--blockedbg);}
  .v-na{color:var(--na);background:var(--nabg);}
  .pills { display:flex; flex-wrap:wrap; gap:8px; margin:12px 0; }
  .pill { border:1px solid var(--line); border-radius:8px; padding:8px 14px; font-size:13px; background:var(--card); }
  .pill b { font-size:18px; display:block; }
  .transition { display:flex; gap:16px; align-items:stretch; margin:12px 0; flex-wrap:wrap; }
  .tcard { flex:1; min-width:200px; border:1px solid var(--line); border-radius:10px; padding:16px; background:var(--card); }
  .tcard .big { font-size:28px; font-weight:700; }
  .ctrl { border:1px solid var(--line); border-radius:10px; padding:16px 18px; margin:12px 0; }
  .ctrl h3 { margin:0 0 4px; font-size:16px; }
  .reason { margin:8px 0; }
  .auto { font-size:12px; color:var(--muted); }
  ul.att { margin:8px 0 0 18px; padding:0; } ul.att li { font-size:13px; color:var(--muted); }
  .foot { margin-top:40px; padding-top:16px; border-top:1px solid var(--line); color:var(--muted); font-size:12px; }
  code { background:var(--nabg); padding:1px 5px; border-radius:4px; font-size:12px; }
  @media print { .wrap{max-width:none;} .ctrl,.meta,.tcard{break-inside:avoid;} }
  @media (max-width:560px){ .meta{grid-template-columns:1fr;} }
</style>
'@
Add '</head><body><div class="wrap">'

Add '<h1>Essential Eight Maturity Level 1 &mdash; Evidence Pack</h1>'
Add ('<div class="sub">Automated assessment of a Microsoft 365 Business Premium tenant. ' +
     'This pack SUPPORTS an assessment; it does not constitute a formal or IRAP-equivalent assessment.</div>')

Add '<div class="meta">'
Add ("<div><b>Tenant</b><br>{0}</div>" -f (HtmlEncode $meta.tenantDomain))
Add ("<div><b>Detected licensing tier</b><br>{0}</div>" -f (HtmlEncode $meta.detectedTier))
Add ("<div><b>Operator</b><br>{0} ({1})</div>" -f (HtmlEncode $meta.studentName), (HtmlEncode $meta.studentId))
Add ("<div><b>Assessing account</b><br>{0}</div>" -f (HtmlEncode $meta.assessingAccount))
Add ("<div><b>Collected (UTC)</b><br>{0}</div>" -f (HtmlEncode $meta.collectedUtc))
Add ("<div><b>Collected (Sydney)</b><br>{0}</div>" -f (HtmlEncode $meta.collectedLocal))
Add ("<div><b>Security Defaults</b><br>{0}</div>" -f (HtmlEncode ([string]$meta.securityDefaults)))
Add ("<div><b>Toolkit / mode</b><br>{0} / {1}</div>" -f (HtmlEncode $meta.toolkitVersion), (HtmlEncode $meta.mode))
Add '</div>'

# --- optional MFA transition highlight ---
if ($Run.transition -and $Run.transition.before -and $Run.transition.after) {
    $b = $Run.transition.before; $a = $Run.transition.after
    Add '<h2>Before &rarr; After (Multi-factor authentication)</h2>'
    Add '<div class="transition">'
    Add ('<div class="tcard"><div class="sub">Before remediation</div>' +
         ('<div class="big"><span class="badge {0}">{1}</span></div>' -f (BadgeClass $b.verdict), (HtmlEncode $b.verdict)) +
         ('<div class="sub">Coverage: {0}%</div></div>' -f (HtmlEncode ([string]$b.coverage.coveragePercent))))
    Add ('<div class="tcard"><div class="sub">After remediation</div>' +
         ('<div class="big"><span class="badge {0}">{1}</span></div>' -f (BadgeClass $a.verdict), (HtmlEncode $a.verdict)) +
         ('<div class="sub">Coverage: {0}%</div></div>' -f (HtmlEncode ([string]$a.coverage.coveragePercent))))
    Add '</div>'
}

# --- summary pills ---
Add '<h2>Summary</h2>'
Add '<div class="pills">'
Add ('<div class="pill"><b>{0}</b>Compliant</div>' -f $counts.Compliant)
Add ('<div class="pill"><b>{0}</b>Partial</div>' -f $counts.Partial)
Add ('<div class="pill"><b>{0}</b>Non-compliant</div>' -f $counts.NonCompliant)
Add ('<div class="pill"><b>{0}</b>Blocked (licensing)</div>' -f $counts.Blocked)
Add ('<div class="pill"><b>{0}</b>Attestation / not assessed</div>' -f $counts.NotAssessed)
Add '</div>'

# --- summary table ---
Add '<table><thead><tr><th>#</th><th>Strategy</th><th>Verdict</th><th>Automatability</th><th>Mode</th></tr></thead><tbody>'
$n = 0
foreach ($r in $results) {
    $n++
    Add ('<tr><td>{0}</td><td>{1}</td><td><span class="badge {2}">{3}</span></td><td>{4}</td><td><code>{5}</code></td></tr>' -f `
        $n, (HtmlEncode $r.strategy), (BadgeClass $r.verdict), (HtmlEncode $r.verdict),
        (HtmlEncode $r.automatability), (HtmlEncode $r.assessmentMode))
}
Add '</tbody></table>'

# --- per-control detail ---
Add '<h2>Control detail</h2>'
foreach ($r in $results) {
    Add '<div class="ctrl">'
    Add ('<h3>{0} <span class="badge {1}">{2}</span></h3>' -f (HtmlEncode $r.strategy), (BadgeClass $r.verdict), (HtmlEncode $r.verdict))
    Add ('<div class="auto"><code>{0}</code> &middot; {1} &middot; collected {2}</div>' -f `
        (HtmlEncode $r.controlId), (HtmlEncode $r.automatability), (HtmlEncode $r.collectedUtc))
    Add ('<p class="reason">{0}</p>' -f (HtmlEncode $r.verdictReason))
    if ($r.attestationQuestions -and @($r.attestationQuestions).Count -gt 0) {
        Add '<div class="sub">Requires attestation:</div><ul class="att">'
        foreach ($q in @($r.attestationQuestions)) { Add ('<li>{0}</li>' -f (HtmlEncode $q)) }
        Add '</ul>'
    }
    Add '</div>'
}

Add '<div class="foot">'
Add ('Generated by the E8 ML1 toolkit ({0}). Scope: Essential Eight Maturity Level 1, Microsoft 365 ' -f (HtmlEncode $meta.toolkitVersion))
Add 'Business Premium, point-in-time. This document supports an assessment and does not constitute a formal '
Add 'or IRAP-equivalent assessment. No credentials or secrets are included. Configuration state is assessed, '
Add 'not control effectiveness.'
Add '</div>'

Add '</div></body></html>'

$outDir = Split-Path -Parent $OutputPath
if ($outDir -and -not (Test-Path -LiteralPath $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
Set-Content -LiteralPath $OutputPath -Value $sb.ToString() -Encoding UTF8
Write-Verbose "Evidence pack written: $OutputPath"
return $OutputPath
