from sigma.pipelines.common import logsource_windows, windows_logsource_mapping
from sigma.processing.transformations import AddConditionTransformation, FieldMappingTransformation, DetectionItemFailureTransformation, RuleFailureTransformation, SetStateTransformation
from sigma.processing.conditions import LogsourceCondition, IncludeFieldCondition, ExcludeFieldCondition, RuleProcessingItemAppliedCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.pipelines.common import logsource_windows_process_creation

# TODO: the following code is just an example extend/adapt as required.
# See https://sigmahq-pysigma.readthedocs.io/en/latest/Processing_Pipelines.html for further documentation.

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
            )
        ],
    )