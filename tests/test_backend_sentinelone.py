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

    assert sentinelone_backend.convert(rule) == ['field = Anycase "foo"']