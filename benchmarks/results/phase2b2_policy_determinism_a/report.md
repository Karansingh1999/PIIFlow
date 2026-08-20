# PIIFlow Policy Benchmark Report

- Cases: 36
- In-scope: 24
- Challenge: 12
- Violations: 20
- Compliant: 16

## Overall

| System | Cases | Precision | Recall | F1 | Accuracy | TP | FP | TN | FN |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| piiflow_policy | 36 | 1.000 | 1.000 | 1.000 | 1.000 | 20 | 0 | 16 | 0 |
| policy_blind | 36 | 0.556 | 1.000 | 0.714 | 0.556 | 20 | 16 | 0 | 0 |

## By Partition

### piiflow_policy

| Group | Cases | Precision | Recall | F1 | Accuracy |
|---|---:|---:|---:|---:|---:|
| challenge | 12 | 1.000 | 1.000 | 1.000 | 1.000 |
| in_scope | 24 | 1.000 | 1.000 | 1.000 | 1.000 |

### policy_blind

| Group | Cases | Precision | Recall | F1 | Accuracy |
|---|---:|---:|---:|---:|---:|
| challenge | 12 | 0.500 | 1.000 | 0.667 | 0.500 |
| in_scope | 24 | 0.583 | 1.000 | 0.737 | 0.583 |


## By Policy Action

### piiflow_policy

| Group | Cases | Precision | Recall | F1 | Accuracy |
|---|---:|---:|---:|---:|---:|
| allow | 15 | 0.000 | 0.000 | 0.000 | 1.000 |
| deny | 17 | 1.000 | 1.000 | 1.000 | 1.000 |
| require_sanitizer | 4 | 1.000 | 1.000 | 1.000 | 1.000 |

### policy_blind

| Group | Cases | Precision | Recall | F1 | Accuracy |
|---|---:|---:|---:|---:|---:|
| allow | 15 | 0.000 | 0.000 | 0.000 | 0.000 |
| deny | 17 | 1.000 | 1.000 | 1.000 | 1.000 |
| require_sanitizer | 4 | 0.750 | 1.000 | 0.857 | 0.750 |


## By Provider

### piiflow_policy

| Group | Cases | Precision | Recall | F1 | Accuracy |
|---|---:|---:|---:|---:|---:|
| anthropic | 4 | 1.000 | 1.000 | 1.000 | 1.000 |
| generic | 6 | 1.000 | 1.000 | 1.000 | 1.000 |
| local | 4 | 1.000 | 1.000 | 1.000 | 1.000 |
| openai | 22 | 1.000 | 1.000 | 1.000 | 1.000 |

### policy_blind

| Group | Cases | Precision | Recall | F1 | Accuracy |
|---|---:|---:|---:|---:|---:|
| anthropic | 4 | 0.750 | 1.000 | 0.857 | 0.750 |
| generic | 6 | 0.667 | 1.000 | 0.800 | 0.667 |
| local | 4 | 0.250 | 1.000 | 0.400 | 0.250 |
| openai | 22 | 0.545 | 1.000 | 0.706 | 0.545 |


## By Trust Zone

### piiflow_policy

| Group | Cases | Precision | Recall | F1 | Accuracy |
|---|---:|---:|---:|---:|---:|
| external | 29 | 1.000 | 1.000 | 1.000 | 1.000 |
| internal | 3 | 1.000 | 1.000 | 1.000 | 1.000 |
| local | 4 | 1.000 | 1.000 | 1.000 | 1.000 |

### policy_blind

| Group | Cases | Precision | Recall | F1 | Accuracy |
|---|---:|---:|---:|---:|---:|
| external | 29 | 0.586 | 1.000 | 0.739 | 0.586 |
| internal | 3 | 0.667 | 1.000 | 0.800 | 0.667 |
| local | 4 | 0.250 | 1.000 | 0.400 | 0.250 |


## By Category

### piiflow_policy

| Group | Cases | Precision | Recall | F1 | Accuracy |
|---|---:|---:|---:|---:|---:|
| EMAIL | 16 | 1.000 | 1.000 | 1.000 | 1.000 |
| FINANCIAL | 6 | 1.000 | 1.000 | 1.000 | 1.000 |
| GOVERNMENT_ID | 3 | 1.000 | 1.000 | 1.000 | 1.000 |
| LOCATION | 3 | 1.000 | 1.000 | 1.000 | 1.000 |
| MEDICAL | 4 | 1.000 | 1.000 | 1.000 | 1.000 |
| PHONE | 4 | 1.000 | 1.000 | 1.000 | 1.000 |

### policy_blind

| Group | Cases | Precision | Recall | F1 | Accuracy |
|---|---:|---:|---:|---:|---:|
| EMAIL | 16 | 0.500 | 1.000 | 0.667 | 0.500 |
| FINANCIAL | 6 | 0.333 | 1.000 | 0.500 | 0.333 |
| GOVERNMENT_ID | 3 | 0.667 | 1.000 | 0.800 | 0.667 |
| LOCATION | 3 | 0.667 | 1.000 | 0.800 | 0.667 |
| MEDICAL | 4 | 0.750 | 1.000 | 0.857 | 0.750 |
| PHONE | 4 | 0.750 | 1.000 | 0.857 | 0.750 |


## False Positives

- piiflow_policy: none
- policy_blind: policy_challenge_attribute_allowed_029, policy_challenge_dict_email_allowed_025, policy_challenge_helper_financial_allowed_default_031, policy_challenge_local_financial_allowed_035, policy_challenge_masked_email_default_allow_034, policy_challenge_request_alias_allowed_027, policy_in_scope_allow_email_openai_001, policy_in_scope_allow_financial_local_016, policy_in_scope_allow_location_internal_018, policy_in_scope_default_allow_email_002, policy_in_scope_default_allow_government_generic_013, policy_in_scope_default_allow_medical_009, policy_in_scope_default_allow_phone_anthropic_011, policy_in_scope_first_match_allows_email_020, policy_in_scope_require_redacted_email_004, policy_in_scope_wrong_trust_zone_no_match_023

## False Negatives

- piiflow_policy: none
- policy_blind: none

## Metadata

```json
{
  "case_count": 36,
  "manifest_hash": "694cf6af4faa5cf7e002a57d650ee3e6ad7aa1204b9d0db0f2c96edcc20a3511",
  "piiflow_version": "0.3.0",
  "platform": "Windows-11-10.0.26200-SP0",
  "policy_content_hash": "be63a102eff6f4c89100221f153f713dda74475662c5783c257d46efd2eddc66",
  "python_version": "3.14.7 (main, Aug 14 2026, 15:39:58) [MSC v.1944 64 bit (AMD64)]",
  "systems": [
    "piiflow_policy",
    "policy_blind"
  ]
}
```