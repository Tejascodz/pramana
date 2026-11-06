# What a Pramana result means

Pramana runs automated tests on an AI system and records the evidence. Read every
report with these limits in mind. This page is a plain-language statement, not legal
advice; if you sell audits built on Pramana, have your own terms reviewed by a lawyer.

## A result is evidence, not a certification

- A Pramana report is test evidence for a qualified human reviewer. It is **not** a
  certification, a conformity assessment, a legal opinion or a regulatory approval, and
  it does not make a system compliant with the EU AI Act, ISO/IEC 42001, the NIST AI RMF,
  India's DPDP Act or any other framework. The control mappings show which requirements
  a test produces evidence for; meeting a requirement is a judgement for the organisation
  and, where the law requires it, a notified body or regulator.
- **A pass covers only what ran.** It applies to the checks that ran, on the inputs,
  probes, model version and number of samples recorded in the pack, on the date of the
  audit. Checks that did not run are listed in the report. A pass is not proof that a
  system is safe, fair or secure; a failure is proof that a problem exists.
- Language models are stochastic and attackers adapt. A system that passed can fail on
  the next request, a new attack or a model update. Re-audit after every change.
- Deterministic scoring has known blind spots, listed in
  [docs/limitations.md](docs/limitations.md). Results flagged *needs review* must be read
  by a person.

## Test only what you are allowed to test

The LLM, access-control and agent checks send real attacks: injected instructions,
attempts to extract data and to claim other people's identities. Run them only against
systems you own or have written permission to test, and never against a production
system without its owner's agreement and a plan for what the test may trigger.

## Data in an audit pack

Pramana runs on your computer or your CI and sends no telemetry. An audit pack contains
the transcripts of every request and reply, hashes of your input files and the results.
If the system under audit returned personal or confidential data, so will the pack:
store and share it as you would the data itself.

## No warranty

Pramana is open-source software under the [MIT licence](LICENSE), provided "as is",
without warranty of any kind. Support and service terms, where offered, are agreed
separately; see [SUPPORT.md](SUPPORT.md).
