import pytest
from sigma.collection import SigmaCollection
from sigma.backends.sentinelone import SentinelOneBackend

@pytest.fixture
def sentinelone_backend():
    return SentinelOneBackend()

def test_sentinelone_simple_eq_nocase_query(sentinelone_backend : SentinelOneBackend):
    rule =  SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                selection:
                    field: foo
                condition: selection
            """)

    assert sentinelone_backend.convert(rule) == ['field In Anycase ("foo")']

def test_sentinelone_single_quote(sentinelone_backend : SentinelOneBackend):
    assert sentinelone_backend.convert(
            SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: process_creation
                    product: windows
                detection:
                    selection:
                        field: fo"o
                    condition: selection
            """)
        ) == ['field In Anycase ("fo\\"o")']

def test_sentinelone_triple_quote(sentinelone_backend : SentinelOneBackend):
    assert sentinelone_backend.convert(
            SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: process_creation
                    product: windows
                detection:
                    selection:
                        field: fo'"o
                    condition: selection
            """)
        ) == ['field In Anycase ("fo\'\\"o")']