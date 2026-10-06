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

## 10.8 First live-tenant run

The eight collectors were then run end to end against the live lab tenant
(SadraLabs.onmicrosoft.com, Business Premium). The pre-flight confirmed the tier and
that Conditional Access, Intune and Defender for Business are all licensed, with
Security Defaults disabled. The results:

| Strategy | Verdict | Basis |
|----------|---------|-------|
| Multi-factor authentication | Compliant | 6 of 6 assessable accounts covered by one enforcing Conditional Access policy |
| Restrict administrative privileges | Partial | one Global Administrator (within the guidance ceiling); process requirements left to attestation |
| Patch applications | NonCompliant | Intune licensed but no managed devices enrolled |
| Patch operating systems | NonCompliant | no managed devices or update policy |
| Configure Microsoft Office macro settings | NonCompliant | no macro policy configured |
| User application hardening | NonCompliant | no browser/hardening policy configured |
| Application control | NotAssessed | endpoint-enforced; attestation only |
| Regular backups | NotAssessed | not determinable from tenant configuration; attestation only |

The run was also the first real test of the collectors' output, and it earned its
keep: it exposed a formatting defect that the unit tests had not. Several verdict
reasons were emitting literal `{0}` placeholders instead of the counts they were meant
to carry, because a PowerShell format expression was binding to only the last piece of
a concatenated string. The fix was small, but the lesson is the same one Section 10.3
drew about runtime compatibility: some faults only appear when the code actually runs
against real data. A static regression test now rejects the specific pattern, so it
cannot return unnoticed.

One result deserves emphasis because it bears on the project's central argument. The
four NonCompliant controls came back NonCompliant and not LicensingBlocked, which is
correct: on Business Premium, Intune and Defender are licensed, so those controls are
assessable and simply not configured. The licensing-blocked path is therefore not
exercised on a Premium tenant at all. Demonstrating criterion S4 requires running the
same collectors against a Business Standard tenant, where the licence genuinely is
absent, and that is the comparison the licensing-ceiling analysis will rest on.

The weaken-assess-remediate-reassess cycle was then run against the same live tenant,
and this time end to end rather than in the earlier isolated lab. The collector removed
the enforcing Conditional Access policy and, polling on the measured coverage until the
directory had actually caught up, recorded NonCompliant at 0%. The policy was recreated
with the break-glass account excluded, and the same collector then recorded Compliant at
100% across the six assessable accounts. The before-and-after pair is the methodology's
whole point: because the identical measurement ran at both ends, the change in verdict
is attributable to the configuration change and nothing else. It also sharpened the
propagation handling. An earlier attempt had the transition come out backwards, because
the wait was polling the Conditional Access policy list, which updates on a faster Graph
replica than the one the collector reads. Tying the wait to the measured coverage, by
the same read path the verdict uses, fixed it.

## 10.9 Updated status against the success criteria

| Criterion | At Milestone B | Now |
|-----------|----------------|-----|
| S1 — assessment produces valid JSON and HTML | Met | Met, demonstrated against a live tenant |
| S2 — the cycle produces a measurable verdict change | Met | Met, demonstrated live (MFA NonCompliant 0% to Compliant 100% on SadraLabs) |
| S3 — at least four strategies fully automated | One of eight | Eight run live; MFA fully automated, the rest returning honest graded or attestation verdicts |
| S4 — at least one control correctly identified as licensing-blocked | Not yet reached | Logic implemented and unit-tested; not triggered on Premium, so demonstration awaits a Business Standard tenant |
| S5 — a second operator can reproduce a run | Not tested | Quickstart exists; a second person has still to attempt it |
| S6 — evidence pack contains no credentials | Met | Met (verified on the live pack) |

The honest qualifier now sits on S4 alone. Everything else has been demonstrated end
to end against a real tenant; S4's licensing-blocked branch is written and tested but,
by the nature of the finding, can only be shown on a tenant that lacks the licence.
