import pytest
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaTransformationError
from sigma.backends.test import TextQueryTestBackend
from sigma.pipelines.sentinelone import sentinelone_pipeline
from sigma.backends.sentinelone import SentinelOneBackend


def test_sentinelone_pipeline():
    assert SentinelOneBackend(processing_pipeline=sentinelone_pipeline()).convert(
        SigmaCollection.from_yaml("""
        title: Process Creation Test
        status: test
        logsource:
            category: process_creation
            product: windows
        detection:
            sel:
                CommandLine: foo.exe
            condition: sel
        """)
    ) == ['SrcProcCmdLine = Anycase "foo.exe"']
 

# https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_susp_adfind_enumeration.yml
def test_sentinelone_adfind_enumerations_pipeline():
    assert SentinelOneBackend(processing_pipeline=sentinelone_pipeline()).convert(
        SigmaCollection.from_yaml("""
        title: Suspicious AdFind Enumeration
        status: test
        logsource:
            category: process_creation
            product: windows
        detection:
            selection_password: #Listing password policy
                CommandLine|contains:
                    - lockoutduration
                    - lockoutthreshold
            selection_enum_ad: #Enumerate Active Directory Admins
                CommandLine|contains: '-sc admincountdmp'
            condition: 1 of selection_*
    """)
    ) == ["SrcProcCmdLine In ContainsCIS (\"lockoutduration\", \"lockoutthreshold\") OR SrcProcCmdLine ContainsCIS \"-sc admincountdmp\""] 


