# Attack Lab scenario evaluation

Open `http://localhost:5050/attack_lab.html`. The visible set is loaded from `configs/security_scenarios.json`; it contains 48 independently authored, inert text cases: six per requested category (two obvious malicious, two evasive malicious, and two benign). Scenario data is stored separately from scanner code. Each case includes its input type, expected label, evasion label, and rationale. Agent cases also include simulated tool/file/network events.

The existing detector rules were not edited to fit these cases. The visible report shows real misses and false alarms from the current limited checks. Some categories have no applicable current rule and therefore have no true positives; this is a measured gap, not an excuse to tune the corpus.

## Visible metrics

- The page labels the four outcomes in plain language: **Attack caught**, **Safe code flagged**, **Attack missed**, and **Safe code allowed**. Precision is correctly flagged attacks divided by everything flagged. Recall is caught attacks divided by all malicious scenarios.
- F1 = harmonic mean of precision and recall.
- Block rate = malicious attempted actions blocked / all malicious attempts. The UI omits it for a selected set when it equals recall. It can differ for agent traces because the existing compiler-pass allowlist can deny a compiler pass, while file and network actions have no corresponding live tool firewall.
- Every metric shows the selected scenario count and the fraction used to calculate it.
- `Lines with no source-scanner match` is the share of nonblank source lines without a match from the four current source patterns. The page reports all configured regex pattern counts (4 source, 2 IR, 5 Attack Lab indicators) and clearly distinguishes this heuristic from general security.

Results include the original input, current scanner verdict, expected label, plain-language outcome, and both detector explanation and scenario rationale. A false-negative panel suggests defensive techniques such as semantic analysis, deobfuscation, taint/data-flow checks, package provenance checks, or sandboxing. These are recommendations, not added rules.

## Held-out cases

`configs/security_heldout.json` is a separate eight-case set marked `held_out_do_not_tune`. It is excluded from the category dropdown, visible metrics, and visible run log. It is loaded only after the user explicitly requests the separate held-out evaluation. Do not use its results to modify rules or scenarios.

## Trace and limitations

Agent traces are explicitly marked as simulated, not live tool execution. The demo can apply the existing compiler-pass allowlist to pass requests. File and network events are labeled as allowed in the simulation because the current prototype has no corresponding live tool firewall. Scenario strings are not executed. These measurements are for this hand-built data only and do not establish general protection.
