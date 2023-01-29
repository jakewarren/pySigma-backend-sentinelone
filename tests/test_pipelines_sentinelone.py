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
    ) == ['SrcProcCmdLine In AnyCase ("foo.exe")']
 

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
    ) == ['SrcProcCmdLine In Contains AnyCase ("lockoutduration", "lockoutthreshold") OR SrcProcCmdLine ContainsCIS "-sc admincountdmp"'] 

def test_sentinelone_cidr_query():
    with pytest.raises(SigmaTransformationError, match="The SentinelOne Deep Visibilty backend does not support CIDR queries."):
        SentinelOneBackend().convert(
            SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: process_creation
                    product: windows
                detection:
                    selection:
                        field|cidr: 192.168.0.0/16
                    condition: selection
            """)
        )
