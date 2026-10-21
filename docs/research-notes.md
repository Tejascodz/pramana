# Research notes and gap analysis

These notes record the research behind Pramana: what the literature and the 2025–2026 regulatory changes say an AI audit needs, where existing tools fall short, and which design choice in Pramana answers each gap. Sources were reviewed in October 2026.

## 1. What an AI audit is expected to produce

**Internal audits need a process, not just metrics.** Raji et al. (2020) proposed SMACTR, an end-to-end internal audit framework with five stages (scoping, mapping, artifact collection, testing, reflection). Each stage produces documents, and together they form the audit report. The point is to catch harms before deployment and to make problems traceable to the decisions that caused them. Pramana implements the five stages directly, and each one writes to the evidence ledger.

**Documentation is part of the evidence.** Model Cards (Mitchell et al., 2019) and Datasheets for Datasets (Gebru et al., 2021) defined what a model and its data should disclose: intended use, out-of-scope use, evaluation across groups, limitations. The EU AI Act turned similar content into legal duties for high-risk systems (Art. 11 technical documentation, Art. 13 information to deployers, Art. 14 human oversight). Pramana scores documentation against these fields and then **reconciles documented claims with measured results**. An overstated AUC in a model card becomes a finding, which is closer to how financial auditors treat management assertions.

**Audits of LLMs need several layers.** Mökander et al. (2023) argue that LLM audits should cover governance (the provider), the model, and the application. Pramana combines governance evidence (classification, documents, owners) with application-level behavioural tests (probes) in one pack.

## 2. Gaps in current tooling

| # | Gap | Evidence | Pramana response |
|---|---|---|---|
| G1 | Tools evaluate but do not create accountability | Ojewale et al. (CHI 2025) interviewed 35 audit practitioners and analysed 435 tools. Most tools focus on evaluation or standards management, and few support the steps that make an audit matter: communicating results, assigning responsibility, and following up. | Each result is mapped to controls, converted into a scored risk with an owner, given a remediation date, and fed into a go/no-go gate with a CI exit code. |
| G2 | Evidence can be edited after the fact | A 2026 practitioner analysis notes that regulators treat mutable application logs as weak evidence, and cites a survey where 78% of ~950 US executives lacked strong confidence they could pass an independent AI governance audit within 90 days. | Append-only, hash-chained ledger; SHA-256 fingerprints of models, data and policy documents; `pramana verify` detects any change. |
| G3 | Fragmented frameworks | NIST AI RMF, ISO/IEC 42001, the EU AI Act, the NIST GenAI profile and sector rules overlap but use different structures. Vendors sell crosswalks as standalone products. | One YAML crosswalk: each test supports controls in six frameworks. Coverage is reported per framework, including what automation cannot evidence. |
| G4 | Agent actions lack traceable authority | The Cloud Security Alliance (Aug 2026) reports that SOC 2 auditors are improvising for AI, and that agents can act without a discrete human request, which current platforms cannot evidence natively. The *Auditable Agents* position paper (arXiv:2604.05485) makes a similar argument about an auditability gap in public agent ecosystems. | `agent.trace_auditability` checks attribution of every tool call to a request, prior human approval for high-impact actions, tool allowlists, ordering and hash-chain integrity. |
| G5 | Western defaults in fairness and privacy | Sambasivan et al. (FAccT 2021) show that fairness in India runs along axes such as caste, religion and region, with different data gaps and proxies. India's AI Governance Guidelines (Nov 2025) call for an India-specific, evidence-based risk framework. | India sutra mapping, an India context-sensitivity rating (documented as a heuristic, not an official tier), Indian identifier patterns (PAN, Aadhaar format, Indian mobile) linked to the DPDP Act, and proxy screening that catches pincode-style features. |
| G6 | Who audits the auditor? | Costanza-Chock, Raji and Buolamwini (FAccT 2022) found weak standards and quality control across the audit field. The CSA note above also reports warnings about templated, look-alike audit reports. | `audit.detector_sensitivity` plants defects of known size and fails if the tests miss them. The case studies double as ground-truth regression tests. |
| G7 | Results do not reach decision makers | Birhane et al. (SaTML 2024) argue that audits only produce accountability when their findings lead to consequences for the audited party. | Plain-English executive summary, an internal-audit style opinion (Effective / Partially effective / Ineffective), named owners and dates, and a release gate. |

## 3. Technical methods and their sources

| Method | Used in | Source |
|---|---|---|
| Four-fifths (80%) rule for adverse impact | `fairness.group_parity` | US Uniform Guidelines on Employee Selection Procedures (1978); formalised for ML by Feldman et al. (KDD 2015) |
| Equal opportunity and equalized odds | `fairness.group_parity` | Hardt, Price and Srebro (NeurIPS 2016) |
| Intersectional evaluation | `fairness.intersectional` | Buolamwini and Gebru, *Gender Shades* (FAT* 2018) |
| Calibration within groups and the trade-off with error-rate parity | `calibration.reliability` | Kleinberg, Mullainathan and Raghavan (ITCS 2017) |
| Expected calibration error | `calibration.reliability` | Guo et al. (ICML 2017) |
| Two-sample tests for dataset shift | `drift.population_stability` | Rabanser, Günnemann and Lipton (NeurIPS 2019); PSI bands are an industry convention in credit risk |
| Loss-threshold membership inference | `privacy.membership_inference` | Yeom et al. (CSF 2018); Shokri et al. (IEEE S&P 2017) |
| Indirect prompt injection | `llm.prompt_injection` | Greshake et al. (AISec 2023) |
| Multi-metric, scenario-based LLM evaluation | LLM checks | Liang et al., HELM (TMLR 2023) |
| Permutation feature importance | `explainability.feature_importance` | Breiman (2001), model-agnostic implementation in scikit-learn |

## 4. Regulatory state as of October 2026

- **EU AI Act.** The Digital Omnibus on AI (Regulation (EU) 2026/1744) entered into force in July 2026. It moved high-risk obligations for stand-alone Annex III systems from 2 August 2026 to 2 December 2027, and for Annex I embedded systems to 2 August 2028. Art. 50 transparency duties and GPAI enforcement kept their August 2026 date. The risk tiers themselves did not change. Credit scoring of natural persons remains high-risk under Annex III point 5(b).
- **India.** MeitY published the India AI Governance Guidelines in November 2025: seven sutras (trust is the foundation; people first; innovation over restraint; fairness and equity; accountability; understandable by design; safety, resilience and sustainability), six pillars, an action plan, and practical guidance. They are voluntary and favour existing laws. The sutras were adapted from the RBI's FREE-AI framework for the financial sector (August 2025). The DPDP Rules were notified in November 2025 with obligations phasing in over 12 to 18 months.
- **United States.** NIST AI RMF 1.0 and the Generative AI Profile (AI 600-1) remain the reference. NIST is developing SP 800-53 control overlays for securing AI systems (COSAiS). For banks, SR 26-2 (April 2026) replaced SR 11-7 as model risk management guidance.
- **Standards and certification.** ISO/IEC 42001 is the certifiable AI management system standard. ISO/IEC 42006 (July 2025) sets requirements for bodies that certify against it, and accreditation programmes are adopting it during 2026. Enterprise buyers increasingly ask vendors for 42001 certification.

The dates Pramana uses are in `src/pramana/controls/data/regulatory_calendar.yaml`, each with a source URL.

## 5. What Pramana deliberately does not claim

Casper et al. (FAccT 2024) show that black-box access limits what an audit can establish; white-box and outside-the-box access (training data, development process) support stronger conclusions. Pramana uses model access where it has it (perturbation, importance, membership inference) and falls back to predictions-only checks otherwise, but it cannot inspect training pipelines or weights. Its LLM probe sets are small samples. Its India rating is a heuristic pending an official framework. See [limitations.md](limitations.md).

## References

1. Raji, I. D., Smart, A., White, R. N., Mitchell, M., Gebru, T., Hutchinson, B., Smith-Loud, J., Theron, D., Barnes, P. *Closing the AI Accountability Gap: Defining an End-to-End Framework for Internal Algorithmic Auditing.* FAT* 2020. [arXiv:2001.00973](https://arxiv.org/abs/2001.00973)
2. Ojewale, V., Steed, R., Vecchione, B., Birhane, A., et al. *Towards AI Accountability Infrastructure: Gaps and Opportunities in AI Audit Tooling.* CHI 2025. [arXiv:2402.17861](https://arxiv.org/abs/2402.17861)
3. Mitchell, M., et al. *Model Cards for Model Reporting.* FAT* 2019. [arXiv:1810.03993](https://arxiv.org/abs/1810.03993)
4. Gebru, T., et al. *Datasheets for Datasets.* Communications of the ACM, 2021. [arXiv:1803.09010](https://arxiv.org/abs/1803.09010)
5. Mökander, J., Schuett, J., Kirk, H. R., Floridi, L. *Auditing Large Language Models: A Three-Layered Approach.* AI and Ethics, 2023. [arXiv:2302.08500](https://arxiv.org/abs/2302.08500)
6. Sambasivan, N., Arnesen, E., Hutchinson, B., Doshi, T., Prabhakaran, V. *Re-imagining Algorithmic Fairness in India and Beyond.* FAccT 2021. [arXiv:2101.09995](https://arxiv.org/abs/2101.09995)
7. Costanza-Chock, S., Raji, I. D., Buolamwini, J. *Who Audits the Auditors? Recommendations from a Field Scan of the Algorithmic Auditing Ecosystem.* FAccT 2022.
8. Birhane, A., Steed, R., Ojewale, V., Vecchione, B., Raji, I. D. *AI Auditing: The Broken Bus on the Road to AI Accountability.* SaTML 2024. [arXiv:2401.14462](https://arxiv.org/abs/2401.14462)
9. Casper, S., et al. *Black-Box Access is Insufficient for Rigorous AI Audits.* FAccT 2024. [arXiv:2401.14446](https://arxiv.org/abs/2401.14446)
10. Huang, K., et al. *AAGATE: A NIST AI RMF-Aligned Governance Platform for Agentic AI.* 2025. [arXiv:2510.25863](https://arxiv.org/abs/2510.25863)
11. *Auditable Agents* (position paper). 2026. [arXiv:2604.05485](https://arxiv.org/abs/2604.05485)
12. Feldman, M., Friedler, S., Moeller, J., Scheidegger, C., Venkatasubramanian, S. *Certifying and Removing Disparate Impact.* KDD 2015. [arXiv:1412.3756](https://arxiv.org/abs/1412.3756)
13. Hardt, M., Price, E., Srebro, N. *Equality of Opportunity in Supervised Learning.* NeurIPS 2016. [arXiv:1610.02413](https://arxiv.org/abs/1610.02413)
14. Buolamwini, J., Gebru, T. *Gender Shades: Intersectional Accuracy Disparities in Commercial Gender Classification.* FAT* 2018 (PMLR 81).
15. Kleinberg, J., Mullainathan, S., Raghavan, M. *Inherent Trade-Offs in the Fair Determination of Risk Scores.* ITCS 2017. [arXiv:1609.05807](https://arxiv.org/abs/1609.05807)
16. Guo, C., Pleiss, G., Sun, Y., Weinberger, K. Q. *On Calibration of Modern Neural Networks.* ICML 2017. [arXiv:1706.04599](https://arxiv.org/abs/1706.04599)
17. Rabanser, S., Günnemann, S., Lipton, Z. C. *Failing Loudly: An Empirical Study of Methods for Detecting Dataset Shift.* NeurIPS 2019. [arXiv:1810.11953](https://arxiv.org/abs/1810.11953)
18. Yeom, S., Giacomelli, I., Fredrikson, M., Jha, S. *Privacy Risk in Machine Learning: Analyzing the Connection to Overfitting.* CSF 2018. [arXiv:1709.01604](https://arxiv.org/abs/1709.01604)
19. Shokri, R., Stronati, M., Song, C., Shmatikov, V. *Membership Inference Attacks against Machine Learning Models.* IEEE S&P 2017. [arXiv:1610.05820](https://arxiv.org/abs/1610.05820)
20. Greshake, K., et al. *Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection.* AISec 2023. [arXiv:2302.12173](https://arxiv.org/abs/2302.12173)
21. Liang, P., et al. *Holistic Evaluation of Language Models.* TMLR 2023. [arXiv:2211.09110](https://arxiv.org/abs/2211.09110)

### Standards, regulation and industry sources

- NIST AI 100-1, AI Risk Management Framework 1.0 (2023): <https://www.nist.gov/itl/ai-risk-management-framework>
- NIST AI 600-1, Generative AI Profile (2024): <https://doi.org/10.6028/NIST.AI.600-1>
- NIST Control Overlays for Securing AI Systems (COSAiS): <https://csrc.nist.gov/projects/risk-management/sp800-53-controls/overlay-repository/nist-developed-overlay-submissions>
- ISO/IEC 42001:2023, AI management systems: <https://www.iso.org/standard/81230.html>
- Regulation (EU) 2024/1689 (AI Act): <https://eur-lex.europa.eu/eli/reg/2024/1689/oj>
- Digital Omnibus on AI timeline: <https://www.jdsupra.com/legalnews/eu-legislators-agree-to-delay-for-high-5617765/> and <https://www.processexcellencenetwork.com/ai/articles/eu-ai-act-2026-what-actually-changed-and-what-deployers-still-must-do>
- India AI Governance Guidelines (MeitY, Nov 2025), PIB explainer: <https://static.pib.gov.in/WriteReadData/specificdocs/documents/2026/feb/doc2026215790801.pdf>
- DPDP Rules notification: <https://www.deccanherald.com/india/centre-notifies-dpdp-rules-implementation-planned-in-phases-spread-over-12-18-months-3798465>
- SR 26-2, Revised Guidance on Model Risk Management (Apr 2026): <https://www.federalreserve.gov/supervisionreg/srletters/sr2602.htm>
- OWASP Top 10 for LLM Applications 2025: <https://genai.owasp.org/llm-top-10/>
- Cloud Security Alliance, *The SOC 2 AI Gap: Auditors Improvise Where AICPA Has Not Acted* (Aug 2026): <https://labs.cloudsecurityalliance.org/research/csa-research-note-soc2-ai-controls-gap-20260830-csa-styled/>
- AI auditability and the executive survey figure: <https://www.unframe.ai/blog/ai-auditability-what-regulators-ask-for>
