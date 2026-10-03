# Milestone B addendum — collectors, tests and continuous integration

This addendum extends Section 10 with work done after the recorded Lab 01 run. The
Milestone B snapshot had one control assessed end to end. Three things have changed
since: the single collector has become a full set of eight, the Lab 01 cycle has been
made safer and more precise, and the project has acquired an automated test suite that
runs on every commit.

## 10.5 From one control to eight

There is now a collector for each of the eight mitigation strategies. Every one returns
the same verdict object, and every one carries an explicit statement of how far it can
be automated: `Automated`, `PartiallyAutomated`, `AttestationOnly` or
`LicensingBlocked`.

That last value carries the project's central argument. A control that cannot be
assessed because the tenant is not licensed for it is now reported as `Blocked`, and
reported separately from a control that was assessed and failed. The patch,
macro-settings and user-application-hardening collectors each check for Intune — and,
for patching, Defender for Business — before they attempt anything else. On a tenant
without those licences they return `Blocked`, with a reason that names the tier and
states plainly that the gap is a purchasing decision, not a configuration failure. This
is the behaviour behind success criterion S4, and it comes straight out of the
licensing-ceiling finding recorded earlier in the report rather than being bolted on
afterwards.

| # | Strategy | Classification |
|---|----------|----------------|
| 1 | Multi-factor authentication | Automated |
| 2 | Restrict administrative privileges | PartiallyAutomated |
| 3 | Patch applications | PartiallyAutomated / LicensingBlocked |
| 4 | Patch operating systems | PartiallyAutomated / LicensingBlocked |
| 5 | Configure Microsoft Office macro settings | PartiallyAutomated / LicensingBlocked |
| 6 | User application hardening | PartiallyAutomated / LicensingBlocked |
| 7 | Application control | AttestationOnly |
| 8 | Regular backups | AttestationOnly |

The partially automated collectors report what Graph can actually see — that a policy
exists, that devices are enrolled, that an update ring is in place — and then hand the
ML1 requirements that configuration cannot answer to the reviewer as attestation
questions, carried in the evidence pack itself. The two attestation-only controls say
so at the top. Application control is enforced on the endpoint through WDAC or AppLocker
and is invisible to Graph; a Microsoft 365 tenant's native retention is flagged, in as
many words, as not being a backup. Stating the attestation boundary in the output
instead of leaving it to be inferred is the response to the attestation-opacity gap
from Section 4.

## 10.6 Hardening the Lab 01 cycle

The weaken, assess, remediate and re-assess cycle has been reworked in two ways, both
of which were flagged as future improvements in the original report.

Assessment is now the safe default. The orchestrator that runs all eight collectors
only ever reads the tenant. Weakening has been moved into a separate script that will
not run without an explicit confirmation flag, checks that it is pointed at the
configured tenant, confirms the break-glass account resolves, and stops if Security
Defaults is still on. Reversing the default this way means the dangerous path has to be
asked for rather than avoided.

The fixed thirty-second propagation wait is gone. In its place a small helper polls a
read-only condition — the lab policy has been removed, or the new policy is present and
enabled — and carries on the moment the directory agrees, giving up only at a timeout.
The cycle no longer sits idle longer than it has to, and it no longer risks taking its
measurement before the change has actually landed.

## 10.7 Automated testing and continuous integration

There is now a Pester suite of twenty-two tests. It covers the parts that can be
exercised without a live tenant: the verdict contract and its validation, the control
register, the Conditional Access coverage logic across inclusion, exclusion and
named-user cases, the configuration placeholder guard, the propagation poller, and the
evidence-pack renderer run against a known-good and a known-bad fixture. All
twenty-two pass.

The suite runs on every push through GitHub Actions, on Windows PowerShell 5.1 and on
PowerShell 7. The second edition is there on purpose. The runtime incompatibility
recorded in Section 10.3 was exactly the sort of fault that only surfaces on first
execution, and the lesson drawn at the time was that version compatibility should be
tested as a matter of course rather than tripped over. Running the whole suite on both
editions at every commit is that test made routine. Each run also parse-checks every
script before the tests, so a syntax error cannot reach the main branch unnoticed.

## 10.8 Updated status against the success criteria

| Criterion | At Milestone B | Now |
|-----------|----------------|-----|
| S1 — assessment produces valid JSON and HTML | Met | Met |
| S2 — the cycle produces a measurable verdict change | Met | Met |
| S3 — at least four strategies fully automated | One of eight | Eight scaffolded; one fully automated, the rest classified honestly and awaiting live validation |
| S4 — at least one control correctly identified as licensing-blocked | Not yet reached | Implemented in the patch, macro and hardening collectors; awaiting live confirmation |
| S5 — a second operator can reproduce a run | Not tested | A copy-paste live-run quickstart now exists; a second person has still to attempt it |
| S6 — evidence pack contains no credentials | Met | Met |

The qualifier on S3 and S4 is worth keeping in view. The eight collectors and the
licensing-block logic are written and unit-tested, but they have not yet been run
against a live tenant. That run is the next step, and it is the point where the
classifications stop being asserted and start being demonstrated.
