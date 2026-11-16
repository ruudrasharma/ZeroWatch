# ZeroWatch test-data pack

Everything needed to test the console and the API without downloading anything. Expected results were
recorded from model `hgb-2026-11-15-eb8ce2fc`; rebuild after any retrain with `python test_data/build.py`.

| File | Use |
|---|---|
| `single_flows.json` | 12 named flows (TC01 to TC12) with the scenario and expected outcome |
| `invalid_inputs.json` | 12 bad flows; every one must return HTTP 422 |
| `batch_normal_20.csv`, `batch_unseen_attacks_20.csv`, `batch_60_flows.csv` | Batch tab (paste or choose file) |
| `batch_60_flows_with_truth.csv` | Same rows with the true label, for checking only |
| `hunt_unseen_attacks_400.csv`, `hunt_normal_100.csv` | Hunt demo: score both in Batch, then Hunt |
| `sample_capture.pcap` | Capture tab: web, mail, DNS, a port scan and a SYN flood |
| `zeek_conn_sample.log` | Capture tab: Zeek conn.log with a scanner and a flooder |
| `expected_results.csv`, `expected_summary.json` | What the model answered for the files above |

## Expected results (model hgb-2026-11-15-eb8ce2fc)

| Input | Verdicts |
|---|---|
| `batch_normal_20.csv` | 19 benign, 1 possible zero-day |
| `batch_unseen_attacks_20.csv` | 12 attack, 4 possible zero-day, 4 benign |
| `hunt_unseen_attacks_400.csv` | 186 attack, 116 possible zero-day, 15 uncertain, 83 benign |
| `hunt_normal_100.csv` | 89 benign, 6 attack, 2 possible zero-day, 3 uncertain |
| `sample_capture.pcap` | 81 benign, 217 attack, 9 possible zero-day, 3 uncertain; scanner 10.0.0.66, flooder 10.0.0.99 |
| `zeek_conn_sample.log` | 50 benign, 159 attack, 1 possible zero-day; flooder 10.1.0.99, scanner 10.1.0.66 |

## Hunt demo with these files

1. Score `hunt_unseen_attacks_400.csv` and `hunt_normal_100.csv` in Batch.
2. Hunt shows 118 suspects in 5 campaigns (about 42, 35, 23, 10 and 8 flows).
3. Label every campaign as attack and retrain. The challenger is promoted (94% on held-back labels).
4. Score the 400-flow file again: no possible zero-days remain and 318 flows are known attacks.

Deliberate weak spots: TC05 (password guessing, labelled Probe) and TC12 (login-heavy session passed as benign).
The capture files are synthetic and contain no real traffic.
