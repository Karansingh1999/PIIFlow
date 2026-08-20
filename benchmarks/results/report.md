# PIIFlow-Bench Report

## Purpose

PIIFlow-Bench measures case-level privacy-flow detection on synthetic Python LLM application examples.

## Benchmark Composition

- Total cases: 90
- In-scope cases: 72
- Challenge cases: 18
- Positive labels: 50
- Negative labels: 40

## Systems Compared

- Lexical co-occurrence baseline
- Direct-flow AST baseline
- PIIFlow legacy mode with structured state disabled
- Full PIIFlow

## Overall Comparison

| System | Cases | Precision | Recall | F1 | Accuracy |
|---|---:|---:|---:|---:|---:|
| direct | 90 | 1.000 | 0.060 | 0.113 | 0.478 |
| lexical | 90 | 0.714 | 1.000 | 0.833 | 0.778 |
| piiflow | 90 | 0.955 | 0.840 | 0.894 | 0.889 |
| piiflow_legacy | 90 | 0.909 | 0.800 | 0.851 | 0.844 |

## In-Scope Comparison

| System | Cases | Precision | Recall | F1 | Accuracy |
|---|---:|---:|---:|---:|---:|
| direct | 72 | 1.000 | 0.083 | 0.154 | 0.542 |
| lexical | 72 | 0.692 | 1.000 | 0.818 | 0.778 |
| piiflow | 72 | 1.000 | 1.000 | 1.000 | 1.000 |
| piiflow_legacy | 72 | 1.000 | 1.000 | 1.000 | 1.000 |

## Challenge Comparison

| System | Cases | Precision | Recall | F1 | Accuracy |
|---|---:|---:|---:|---:|---:|
| direct | 18 | 0.000 | 0.000 | 0.000 | 0.222 |
| lexical | 18 | 0.778 | 1.000 | 0.875 | 0.778 |
| piiflow | 18 | 0.750 | 0.429 | 0.545 | 0.444 |
| piiflow_legacy | 18 | 0.500 | 0.286 | 0.364 | 0.222 |

## Family-Level Results

### direct

| Family | Cases | Precision | Recall | F1 |
|---|---:|---:|---:|---:|
| ambiguous_call | 2 | 0.000 | 0.000 | 0.000 |
| annotated_assignment | 2 | 0.000 | 0.000 | 0.000 |
| anthropic_messages | 2 | 0.000 | 0.000 | 0.000 |
| assignment | 1 | 0.000 | 0.000 | 0.000 |
| async_function | 2 | 0.000 | 0.000 | 0.000 |
| await_sink | 2 | 0.000 | 0.000 | 0.000 |
| closure | 1 | 0.000 | 0.000 | 0.000 |
| complex_collection_aliasing | 1 | 0.000 | 0.000 | 0.000 |
| concatenation | 1 | 0.000 | 0.000 | 0.000 |
| conditional_expression | 1 | 0.000 | 0.000 | 0.000 |
| container | 6 | 0.000 | 0.000 | 0.000 |
| decorator_modified_behavior | 1 | 0.000 | 0.000 | 0.000 |
| dependency_defined_helper | 1 | 0.000 | 0.000 | 0.000 |
| direct_request_subscript | 3 | 1.000 | 1.000 | 1.000 |
| dynamic_attribute_access | 1 | 0.000 | 0.000 | 0.000 |
| dynamic_import | 1 | 0.000 | 0.000 | 0.000 |
| dynamic_sink_construction | 1 | 0.000 | 0.000 | 0.000 |
| encoding | 2 | 0.000 | 0.000 | 0.000 |
| exception_flow | 1 | 0.000 | 0.000 | 0.000 |
| field_sensitive_dictionary | 1 | 0.000 | 0.000 | 0.000 |
| framework_generated_value | 1 | 0.000 | 0.000 | 0.000 |
| fstring | 1 | 0.000 | 0.000 | 0.000 |
| generator_flow | 1 | 0.000 | 0.000 | 0.000 |
| generic_invoke | 4 | 0.000 | 0.000 | 0.000 |
| get_source | 2 | 0.000 | 0.000 | 0.000 |
| hashing | 2 | 0.000 | 0.000 | 0.000 |
| implicit_control_flow | 1 | 0.000 | 0.000 | 0.000 |
| import_resolution | 4 | 0.000 | 0.000 | 0.000 |
| interprocedural | 3 | 0.000 | 0.000 | 0.000 |
| interprocedural_chain | 1 | 0.000 | 0.000 | 0.000 |
| keyword_argument | 1 | 0.000 | 0.000 | 0.000 |
| method_binding | 6 | 0.000 | 0.000 | 0.000 |
| module_collision | 2 | 0.000 | 0.000 | 0.000 |
| multiple_categories | 1 | 0.000 | 0.000 | 0.000 |
| multiple_runtime_targets | 1 | 0.000 | 0.000 | 0.000 |
| nested_function_complexity | 1 | 0.000 | 0.000 | 0.000 |
| object_attribute_storage | 1 | 0.000 | 0.000 | 0.000 |
| openai_chat | 2 | 0.000 | 0.000 | 0.000 |
| reassignment | 1 | 0.000 | 0.000 | 0.000 |
| reflection | 1 | 0.000 | 0.000 | 0.000 |
| request_alias | 1 | 0.000 | 0.000 | 0.000 |
| request_args | 2 | 0.000 | 0.000 | 0.000 |
| request_form | 2 | 0.000 | 0.000 | 0.000 |
| safe_public | 3 | 0.000 | 0.000 | 0.000 |
| sanitizer | 7 | 0.000 | 0.000 | 0.000 |
| sensitive_looking_name | 2 | 0.000 | 0.000 | 0.000 |
| unknown_call | 2 | 0.000 | 0.000 | 0.000 |
| unresolved_polymorphic_method | 1 | 0.000 | 0.000 | 0.000 |

### lexical

| Family | Cases | Precision | Recall | F1 |
|---|---:|---:|---:|---:|
| ambiguous_call | 2 | 1.000 | 1.000 | 1.000 |
| annotated_assignment | 2 | 1.000 | 1.000 | 1.000 |
| anthropic_messages | 2 | 1.000 | 1.000 | 1.000 |
| assignment | 1 | 1.000 | 1.000 | 1.000 |
| async_function | 2 | 0.500 | 1.000 | 0.667 |
| await_sink | 2 | 1.000 | 1.000 | 1.000 |
| closure | 1 | 1.000 | 1.000 | 1.000 |
| complex_collection_aliasing | 1 | 0.000 | 0.000 | 0.000 |
| concatenation | 1 | 1.000 | 1.000 | 1.000 |
| conditional_expression | 1 | 1.000 | 1.000 | 1.000 |
| container | 6 | 0.750 | 1.000 | 0.857 |
| decorator_modified_behavior | 1 | 0.000 | 0.000 | 0.000 |
| dependency_defined_helper | 1 | 1.000 | 1.000 | 1.000 |
| direct_request_subscript | 3 | 1.000 | 1.000 | 1.000 |
| dynamic_attribute_access | 1 | 1.000 | 1.000 | 1.000 |
| dynamic_import | 1 | 1.000 | 1.000 | 1.000 |
| dynamic_sink_construction | 1 | 1.000 | 1.000 | 1.000 |
| encoding | 2 | 1.000 | 1.000 | 1.000 |
| exception_flow | 1 | 1.000 | 1.000 | 1.000 |
| field_sensitive_dictionary | 1 | 0.000 | 0.000 | 0.000 |
| framework_generated_value | 1 | 1.000 | 1.000 | 1.000 |
| fstring | 1 | 1.000 | 1.000 | 1.000 |
| generator_flow | 1 | 1.000 | 1.000 | 1.000 |
| generic_invoke | 4 | 1.000 | 1.000 | 1.000 |
| get_source | 2 | 1.000 | 1.000 | 1.000 |
| hashing | 2 | 1.000 | 1.000 | 1.000 |
| implicit_control_flow | 1 | 1.000 | 1.000 | 1.000 |
| import_resolution | 4 | 0.500 | 1.000 | 0.667 |
| interprocedural | 3 | 0.500 | 1.000 | 0.667 |
| interprocedural_chain | 1 | 1.000 | 1.000 | 1.000 |
| keyword_argument | 1 | 1.000 | 1.000 | 1.000 |
| method_binding | 6 | 0.750 | 1.000 | 0.857 |
| module_collision | 2 | 0.500 | 1.000 | 0.667 |
| multiple_categories | 1 | 1.000 | 1.000 | 1.000 |
| multiple_runtime_targets | 1 | 0.000 | 0.000 | 0.000 |
| nested_function_complexity | 1 | 1.000 | 1.000 | 1.000 |
| object_attribute_storage | 1 | 1.000 | 1.000 | 1.000 |
| openai_chat | 2 | 1.000 | 1.000 | 1.000 |
| reassignment | 1 | 0.000 | 0.000 | 0.000 |
| reflection | 1 | 1.000 | 1.000 | 1.000 |
| request_alias | 1 | 1.000 | 1.000 | 1.000 |
| request_args | 2 | 1.000 | 1.000 | 1.000 |
| request_form | 2 | 1.000 | 1.000 | 1.000 |
| safe_public | 3 | 0.000 | 0.000 | 0.000 |
| sanitizer | 7 | 0.143 | 1.000 | 0.250 |
| sensitive_looking_name | 2 | 0.000 | 0.000 | 0.000 |
| unknown_call | 2 | 1.000 | 1.000 | 1.000 |
| unresolved_polymorphic_method | 1 | 1.000 | 1.000 | 1.000 |

### piiflow

| Family | Cases | Precision | Recall | F1 |
|---|---:|---:|---:|---:|
| ambiguous_call | 2 | 1.000 | 1.000 | 1.000 |
| annotated_assignment | 2 | 1.000 | 1.000 | 1.000 |
| anthropic_messages | 2 | 1.000 | 1.000 | 1.000 |
| assignment | 1 | 1.000 | 1.000 | 1.000 |
| async_function | 2 | 1.000 | 1.000 | 1.000 |
| await_sink | 2 | 1.000 | 1.000 | 1.000 |
| closure | 1 | 0.000 | 0.000 | 0.000 |
| complex_collection_aliasing | 1 | 0.000 | 0.000 | 0.000 |
| concatenation | 1 | 1.000 | 1.000 | 1.000 |
| conditional_expression | 1 | 1.000 | 1.000 | 1.000 |
| container | 6 | 1.000 | 1.000 | 1.000 |
| decorator_modified_behavior | 1 | 0.000 | 0.000 | 0.000 |
| dependency_defined_helper | 1 | 1.000 | 1.000 | 1.000 |
| direct_request_subscript | 3 | 1.000 | 1.000 | 1.000 |
| dynamic_attribute_access | 1 | 0.000 | 0.000 | 0.000 |
| dynamic_import | 1 | 1.000 | 1.000 | 1.000 |
| dynamic_sink_construction | 1 | 0.000 | 0.000 | 0.000 |
| encoding | 2 | 1.000 | 1.000 | 1.000 |
| exception_flow | 1 | 0.000 | 0.000 | 0.000 |
| field_sensitive_dictionary | 1 | 0.000 | 0.000 | 0.000 |
| framework_generated_value | 1 | 0.000 | 0.000 | 0.000 |
| fstring | 1 | 1.000 | 1.000 | 1.000 |
| generator_flow | 1 | 0.000 | 0.000 | 0.000 |
| generic_invoke | 4 | 1.000 | 1.000 | 1.000 |
| get_source | 2 | 1.000 | 1.000 | 1.000 |
| hashing | 2 | 1.000 | 1.000 | 1.000 |
| implicit_control_flow | 1 | 0.000 | 0.000 | 0.000 |
| import_resolution | 4 | 1.000 | 1.000 | 1.000 |
| interprocedural | 3 | 1.000 | 1.000 | 1.000 |
| interprocedural_chain | 1 | 1.000 | 1.000 | 1.000 |
| keyword_argument | 1 | 1.000 | 1.000 | 1.000 |
| method_binding | 6 | 1.000 | 1.000 | 1.000 |
| module_collision | 2 | 1.000 | 1.000 | 1.000 |
| multiple_categories | 1 | 1.000 | 1.000 | 1.000 |
| multiple_runtime_targets | 1 | 0.000 | 0.000 | 0.000 |
| nested_function_complexity | 1 | 0.000 | 0.000 | 0.000 |
| object_attribute_storage | 1 | 1.000 | 1.000 | 1.000 |
| openai_chat | 2 | 1.000 | 1.000 | 1.000 |
| reassignment | 1 | 0.000 | 0.000 | 0.000 |
| reflection | 1 | 1.000 | 1.000 | 1.000 |
| request_alias | 1 | 1.000 | 1.000 | 1.000 |
| request_args | 2 | 1.000 | 1.000 | 1.000 |
| request_form | 2 | 1.000 | 1.000 | 1.000 |
| safe_public | 3 | 0.000 | 0.000 | 0.000 |
| sanitizer | 7 | 1.000 | 1.000 | 1.000 |
| sensitive_looking_name | 2 | 0.000 | 0.000 | 0.000 |
| unknown_call | 2 | 1.000 | 1.000 | 1.000 |
| unresolved_polymorphic_method | 1 | 1.000 | 1.000 | 1.000 |

### piiflow_legacy

| Family | Cases | Precision | Recall | F1 |
|---|---:|---:|---:|---:|
| ambiguous_call | 2 | 1.000 | 1.000 | 1.000 |
| annotated_assignment | 2 | 1.000 | 1.000 | 1.000 |
| anthropic_messages | 2 | 1.000 | 1.000 | 1.000 |
| assignment | 1 | 1.000 | 1.000 | 1.000 |
| async_function | 2 | 1.000 | 1.000 | 1.000 |
| await_sink | 2 | 1.000 | 1.000 | 1.000 |
| closure | 1 | 0.000 | 0.000 | 0.000 |
| complex_collection_aliasing | 1 | 0.000 | 0.000 | 0.000 |
| concatenation | 1 | 1.000 | 1.000 | 1.000 |
| conditional_expression | 1 | 1.000 | 1.000 | 1.000 |
| container | 6 | 1.000 | 1.000 | 1.000 |
| decorator_modified_behavior | 1 | 0.000 | 0.000 | 0.000 |
| dependency_defined_helper | 1 | 1.000 | 1.000 | 1.000 |
| direct_request_subscript | 3 | 1.000 | 1.000 | 1.000 |
| dynamic_attribute_access | 1 | 0.000 | 0.000 | 0.000 |
| dynamic_import | 1 | 1.000 | 1.000 | 1.000 |
| dynamic_sink_construction | 1 | 0.000 | 0.000 | 0.000 |
| encoding | 2 | 1.000 | 1.000 | 1.000 |
| exception_flow | 1 | 0.000 | 0.000 | 0.000 |
| field_sensitive_dictionary | 1 | 0.000 | 0.000 | 0.000 |
| framework_generated_value | 1 | 0.000 | 0.000 | 0.000 |
| fstring | 1 | 1.000 | 1.000 | 1.000 |
| generator_flow | 1 | 0.000 | 0.000 | 0.000 |
| generic_invoke | 4 | 1.000 | 1.000 | 1.000 |
| get_source | 2 | 1.000 | 1.000 | 1.000 |
| hashing | 2 | 1.000 | 1.000 | 1.000 |
| implicit_control_flow | 1 | 0.000 | 0.000 | 0.000 |
| import_resolution | 4 | 1.000 | 1.000 | 1.000 |
| interprocedural | 3 | 1.000 | 1.000 | 1.000 |
| interprocedural_chain | 1 | 1.000 | 1.000 | 1.000 |
| keyword_argument | 1 | 1.000 | 1.000 | 1.000 |
| method_binding | 6 | 1.000 | 1.000 | 1.000 |
| module_collision | 2 | 1.000 | 1.000 | 1.000 |
| multiple_categories | 1 | 1.000 | 1.000 | 1.000 |
| multiple_runtime_targets | 1 | 0.000 | 0.000 | 0.000 |
| nested_function_complexity | 1 | 0.000 | 0.000 | 0.000 |
| object_attribute_storage | 1 | 0.000 | 0.000 | 0.000 |
| openai_chat | 2 | 1.000 | 1.000 | 1.000 |
| reassignment | 1 | 0.000 | 0.000 | 0.000 |
| reflection | 1 | 1.000 | 1.000 | 1.000 |
| request_alias | 1 | 0.000 | 0.000 | 0.000 |
| request_args | 2 | 1.000 | 1.000 | 1.000 |
| request_form | 2 | 1.000 | 1.000 | 1.000 |
| safe_public | 3 | 0.000 | 0.000 | 0.000 |
| sanitizer | 7 | 1.000 | 1.000 | 1.000 |
| sensitive_looking_name | 2 | 0.000 | 0.000 | 0.000 |
| unknown_call | 2 | 1.000 | 1.000 | 1.000 |
| unresolved_polymorphic_method | 1 | 1.000 | 1.000 | 1.000 |


## Category-Level Results

### direct

| Category | Precision | Recall | F1 |
|---|---:|---:|---:|
| EMAIL | 1.000 | 0.050 | 0.095 |
| FINANCIAL | 0.000 | 0.000 | 0.000 |
| GOVERNMENT_ID | 0.000 | 0.000 | 0.000 |
| LOCATION | 1.000 | 0.250 | 0.400 |
| MEDICAL | 0.000 | 0.000 | 0.000 |
| PHONE | 1.000 | 0.125 | 0.222 |

### lexical

| Category | Precision | Recall | F1 |
|---|---:|---:|---:|
| EMAIL | 0.588 | 1.000 | 0.741 |
| FINANCIAL | 0.778 | 1.000 | 0.875 |
| GOVERNMENT_ID | 0.800 | 1.000 | 0.889 |
| LOCATION | 0.800 | 1.000 | 0.889 |
| MEDICAL | 0.889 | 1.000 | 0.941 |
| PHONE | 0.889 | 1.000 | 0.941 |

### piiflow

| Category | Precision | Recall | F1 |
|---|---:|---:|---:|
| EMAIL | 0.889 | 0.800 | 0.842 |
| FINANCIAL | 1.000 | 0.857 | 0.923 |
| GOVERNMENT_ID | 1.000 | 0.750 | 0.857 |
| LOCATION | 1.000 | 1.000 | 1.000 |
| MEDICAL | 1.000 | 0.875 | 0.933 |
| PHONE | 1.000 | 0.875 | 0.933 |

### piiflow_legacy

| Category | Precision | Recall | F1 |
|---|---:|---:|---:|
| EMAIL | 0.778 | 0.700 | 0.737 |
| FINANCIAL | 1.000 | 0.857 | 0.923 |
| GOVERNMENT_ID | 1.000 | 0.750 | 0.857 |
| LOCATION | 1.000 | 1.000 | 1.000 |
| MEDICAL | 1.000 | 0.875 | 0.933 |
| PHONE | 1.000 | 0.875 | 0.933 |


## Sink-Level Results

### direct

| Sink tag | Cases | Precision | Recall | F1 |
|---|---:|---:|---:|---:|
| anthropic | 8 | 0.000 | 0.000 | 0.000 |
| generic | 5 | 0.000 | 0.000 | 0.000 |
| openai | 77 | 1.000 | 0.070 | 0.130 |

### lexical

| Sink tag | Cases | Precision | Recall | F1 |
|---|---:|---:|---:|---:|
| anthropic | 8 | 0.667 | 1.000 | 0.800 |
| generic | 5 | 0.750 | 1.000 | 0.857 |
| openai | 77 | 0.717 | 1.000 | 0.835 |

### piiflow

| Sink tag | Cases | Precision | Recall | F1 |
|---|---:|---:|---:|---:|
| anthropic | 8 | 1.000 | 1.000 | 1.000 |
| generic | 5 | 1.000 | 1.000 | 1.000 |
| openai | 77 | 0.946 | 0.814 | 0.875 |

### piiflow_legacy

| Sink tag | Cases | Precision | Recall | F1 |
|---|---:|---:|---:|---:|
| anthropic | 8 | 1.000 | 1.000 | 1.000 |
| generic | 5 | 1.000 | 1.000 | 1.000 |
| openai | 77 | 0.892 | 0.767 | 0.825 |


## False Positives

- direct: none
- lexical: challenge_collection_alias_safe_011, challenge_decorator_sanitizes_safe_008, challenge_dict_field_safe_001, challenge_runtime_target_safe_014, in_scope_async_redacted_safe_053, in_scope_financial_masked_safe_071, in_scope_government_redacted_safe_070, in_scope_helper_constant_safe_041, in_scope_import_alias_constant_safe_059, in_scope_import_helper_constant_safe_058, in_scope_instance_constant_safe_055, in_scope_list_public_sensitive_local_safe_066, in_scope_location_anonymized_safe_072, in_scope_masked_phone_safe_043, in_scope_reassignment_kills_taint_safe_040, in_scope_redacted_email_safe_037, in_scope_redacted_medical_safe_044, in_scope_same_named_safe_local_safe_060, in_scope_sensitive_not_sent_safe_048, in_scope_sink_public_sensitive_local_safe_049
- piiflow: challenge_decorator_sanitizes_safe_008, challenge_runtime_target_safe_014
- piiflow_legacy: challenge_collection_alias_safe_011, challenge_decorator_sanitizes_safe_008, challenge_dict_field_safe_001, challenge_runtime_target_safe_014

## False Negatives

- direct: challenge_attribute_storage_vulnerable_002, challenge_closure_vulnerable_009, challenge_dependency_helper_vulnerable_012, challenge_dynamic_attribute_vulnerable_016, challenge_dynamic_import_vulnerable_006, challenge_dynamic_sink_vulnerable_005, challenge_exception_flow_vulnerable_017, challenge_framework_value_vulnerable_015, challenge_generator_vulnerable_010, challenge_implicit_control_vulnerable_004, challenge_nested_function_vulnerable_018, challenge_polymorphic_method_vulnerable_013, challenge_reflection_helper_vulnerable_007, challenge_request_alias_vulnerable_003, in_scope_ambiguous_call_conservative_028, in_scope_annotated_medical_anthropic_006, in_scope_anthropic_phone_030, in_scope_args_phone_033, in_scope_assignment_financial_chat_005, in_scope_async_medical_020, in_scope_await_email_021, in_scope_base64_financial_015, in_scope_class_method_government_024, in_scope_concat_phone_008, in_scope_conditional_email_012, in_scope_dict_location_anthropic_011, in_scope_explicit_import_email_025, in_scope_form_email_032, in_scope_fstring_email_007, in_scope_generic_medical_031, in_scope_get_json_government_004, in_scope_hashing_financial_014, in_scope_helper_email_016, in_scope_import_alias_email_026, in_scope_instance_method_email_022, in_scope_keyword_helper_location_019, in_scope_list_medical_chat_009, in_scope_multi_category_034, in_scope_openai_chat_financial_029, in_scope_positional_invoke_financial_036, in_scope_positional_invoke_phone_018, in_scope_same_named_vulnerable_027, in_scope_sanitized_copy_original_tainted_035, in_scope_static_method_phone_023, in_scope_tuple_financial_chat_010, in_scope_two_function_medical_017, in_scope_unknown_call_government_013
- lexical: none
- piiflow: challenge_closure_vulnerable_009, challenge_dynamic_attribute_vulnerable_016, challenge_dynamic_sink_vulnerable_005, challenge_exception_flow_vulnerable_017, challenge_framework_value_vulnerable_015, challenge_generator_vulnerable_010, challenge_implicit_control_vulnerable_004, challenge_nested_function_vulnerable_018
- piiflow_legacy: challenge_attribute_storage_vulnerable_002, challenge_closure_vulnerable_009, challenge_dynamic_attribute_vulnerable_016, challenge_dynamic_sink_vulnerable_005, challenge_exception_flow_vulnerable_017, challenge_framework_value_vulnerable_015, challenge_generator_vulnerable_010, challenge_implicit_control_vulnerable_004, challenge_nested_function_vulnerable_018, challenge_request_alias_vulnerable_003

## Runtime Statistics

| System | Mean seconds | Median seconds | P95 seconds | Total seconds |
|---|---:|---:|---:|---:|
| direct | 0.008 | 0.008 | 0.012 | 0.749 |
| lexical | 0.004 | 0.004 | 0.005 | 0.385 |
| piiflow | 0.005 | 0.005 | 0.006 | 0.474 |
| piiflow_legacy | 0.005 | 0.005 | 0.007 | 0.493 |

## Interpretation

These numbers compare PIIFlow with two intentionally weak transparent baselines. They do not establish superiority over state-of-the-art static-analysis systems.

## Threats To Validity

- Benchmark cases are synthetic and smaller than production repositories.
- The analyzer authors also constructed the benchmark.
- Baselines are intentionally simple and are not state-of-the-art analyzers.
- Python dynamic behavior is only partially represented.
- Case-level binary metrics do not fully measure source-to-sink path quality.
- Similarity between development tests and benchmark cases may inflate performance.
- The challenge set is not exhaustive.
- Category labels may not capture every privacy-policy nuance.
- High performance does not imply legal or regulatory compliance.
- Results must not be generalized to other programming languages.
- Benchmark performance does not prove superiority over CodeQL, Pysa, or commercial systems.

## Known Limitations

Challenge cases intentionally include documented unsupported or partially supported behavior. Failures are retained rather than relabeled.

## Reproduction Commands

```bash
uv run python benchmarks/run.py --partition all --system all
```

## Metadata

```json
{
  "benchmark_content_changed_during_run": false,
  "benchmark_content_hash": "a34c9817f0da31aaf4bd8a9590796614c62cbf33137b6486c3192d794f361f94",
  "git_commit": "unavailable",
  "manifest_hash": "2335f30a119652db32aca3163e4b1a4d91a1e2bb8331cec51d247cd444ee51c7",
  "manifest_version": 1,
  "partition": "all",
  "piiflow_version": "0.3.0",
  "platform": "Windows-11-10.0.26200-SP0",
  "python_version": "3.14.7 (main, Aug 14 2026, 15:39:58) [MSC v.1944 64 bit (AMD64)]",
  "systems": [
    "lexical",
    "direct",
    "piiflow_legacy",
    "piiflow"
  ]
}
```