from sigma.pipelines.common import logsource_windows, windows_logsource_mapping
from sigma.processing.transformations import AddConditionTransformation, FieldMappingTransformation, DetectionItemFailureTransformation, RuleFailureTransformation, SetStateTransformation, ReplaceStringTransformation, ValueTransformation
from sigma.processing.conditions import IncludeFieldCondition, MatchStringCondition, LogsourceCondition, RuleProcessingItemAppliedCondition, RuleProcessingCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.pipelines.common import logsource_windows_process_creation
from sigma.types import SigmaString, SigmaCIDRExpression
import re
from sigma.rule import SigmaRule

# See https://sigmahq-pysigma.readthedocs.io/en/latest/Processing_Pipelines.html for further documentation.

class AggregateRuleProcessingCondition(RuleProcessingCondition):
    """"""
    def match(self, pipeline : "sigma.processing.pipeline.ProcessingPipeline", rule : SigmaRule) -> bool:
        """Match condition on Sigma rule."""
        agg_function_strings = ["| count", "| min", "| max", "| avg", "| sum", "| near"]
        condition_string = " ".join([item.lower() for item in rule.detection.condition])
        if any(f in condition_string for f in agg_function_strings):
            return True
        else:
            return False

class CIDRRuleProcessingCondition(RuleProcessingCondition):
    """"""
    def match(self, pipeline : "sigma.processing.pipeline.ProcessingPipeline", rule : SigmaRule) -> bool:
        """Match on Sigma rule with CIDR modifier."""
        for i in rule.detection.detections:
            for d_items in rule.detection.detections[i].detection_items:
                if any(isinstance(d,SigmaCIDRExpression) for d in d_items.value):
                    return True
                else:
                    return False




def sentinelone_pipeline() -> ProcessingPipeline:        # Processing pipelines should be defined as functions that return a ProcessingPipeline object.
    return ProcessingPipeline(
        name="pySigma-pipeline-sentinelone example pipeline",
        priority=20,            # The priority defines the order pipelines are applied. See documentation for common values.
        items= [
            ProcessingItem(     # Field mappings
                identifier="sentinelone_field_mapping",
                transformation=FieldMappingTransformation({
                    "CommandLine": "SrcProcCmdLine",     
                }),
            ),

            # Handle rules that use aggregate functions
            ProcessingItem(
                identifier="sentinelone_fail_rule_conditions_not_supported",
                transformation=RuleFailureTransformation("Rules with aggregate function conditions like count, min, max, avg, sum, and near are not supported by the SentinelOne Sigma backend!"),
                rule_conditions=[
                    AggregateRuleProcessingCondition()
                ],
            ),

            # Handle rules that use CIDR modifier
            ProcessingItem(
                identifier="sentinelone_cidr_not_supported",
                transformation=DetectionItemFailureTransformation("The SentinelOne Deep Visibilty backend does not support CIDR queries."),
                rule_conditions=[
                    CIDRRuleProcessingCondition(),
                ]
            ),
        ],
    )