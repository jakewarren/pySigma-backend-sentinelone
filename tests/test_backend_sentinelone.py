import pytest
from sigma.collection import SigmaCollection
from sigma.backends.sentinelone import SentinelOneBackend

@pytest.fixture
def sentinelone_backend():
    return SentinelOneBackend()

def test_sentinelone_simple_eq_nocase_query(sentinelone_backend : SentinelOneBackend):
    assert sentinelone_backend.convert( 
        SigmaCollection.from_yaml("""
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
     ) == ['field In Anycase ("foo")']

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

def test_sentinelone_not_condition_query(sentinelone_backend : SentinelOneBackend):
    assert sentinelone_backend.convert(
            SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: process_creation
                    product: windows
                detection:
                    selection:
                        field: foo
                    filter:
                        field: blah
                    condition: selection and not filter
            """)
        ) == ['field In Anycase ("foo") AND NOT field In Anycase ("blah")']


def test_sentinelone_simple_contains_query(sentinelone_backend : SentinelOneBackend):
    assert sentinelone_backend.convert(
            SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: process_creation
                    product: windows
                detection:
                    selection:
                        field|contains: foo
                    condition: selection
            """)
        ) == ['field ContainsCIS "foo"']

def test_sentinelone_simple_startswith_query(sentinelone_backend : SentinelOneBackend):
    assert sentinelone_backend.convert(
            SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: process_creation
                    product: windows
                detection:
                    selection:
                        field|startswith: foo
                    condition: selection
            """)
        ) == ['field StartsWithCIS "foo"']

def test_sentinelone_simple_endswith_query(sentinelone_backend : SentinelOneBackend):
    assert sentinelone_backend.convert(
            SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: process_creation
                    product: windows
                detection:
                    selection:
                        field|endswith: foo
                    condition: selection
            """)
        ) == ['field EndsWithCIS "foo"']

def test_sentinelone_value_in_list_query(sentinelone_backend : SentinelOneBackend):
    assert sentinelone_backend.convert(
            SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: process_creation
                    product: windows
                detection:
                    selection:
                        field:
                            - 'val1'
                            - 'val2'
                            - 'val3'
                    condition: selection
            """)
        ) == ['field In AnyCase ("val1", "val2", "val3")']


def test_sentinelone_value_eq_or_query(sentinelone_backend : SentinelOneBackend):
    assert sentinelone_backend.convert(
            SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: process_creation
                    product: windows
                detection:
                    selection:
                        field1: val1
                    selection2:
                        field2: val2
                    condition: selection or selection2
            """)
        ) == ['field1 In Anycase ("val1") OR field2 In Anycase ("val2")']


def test_sentinelone_value_eq_and_query(sentinelone_backend : SentinelOneBackend):
    assert sentinelone_backend.convert(
            SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: process_creation
                    product: windows
                detection:
                    selection:
                        field: val1
                    selection2:
                        field2: val2
                    condition: selection and selection2
            """)
        ) == ['field In Anycase ("val1") AND field2 In Anycase ("val2")']

def test_sentinelone_contains_any_query(sentinelone_backend : SentinelOneBackend):
    assert sentinelone_backend.convert(
            SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: process_creation
                    product: windows
                detection:
                    selection:
                        field|contains:
                            - 'val1'
                            - 'val2'
                            - 'val3'
                    condition: selection
            """)
        ) == ['field In Contains Anycase ("val1", "val2", "val3")']

def test_sentinelone_contains_all_query(sentinelone_backend : SentinelOneBackend):
    assert sentinelone_backend.convert(
            SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: process_creation
                    product: windows
                detection:
                    selection:
                        field|contains|all:
                            - 'val1'
                            - 'val2'
                            - 'val3'
                    condition: selection
            """)
        ) == ['field ContainsCIS "val1" AND field ContainsCIS "val2" AND field ContainsCIS "val3"']

def test_sentinelone_startswith_any_query(sentinelone_backend : SentinelOneBackend):
    assert sentinelone_backend.convert(
            SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: process_creation
                    product: windows
                detection:
                    selection:
                        field|startswith:
                            - 'val1'
                            - 'val2'
                            - 'val3'
                    condition: selection
            """)
        ) == ['field StartsWithCIS "val1" OR field StartsWithCIS "val2" OR field StartsWithCIS "val3"']

def test_sentinelone_endswith_any_query(sentinelone_backend : SentinelOneBackend):
    assert sentinelone_backend.convert(
            SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: process_creation
                    product: windows
                detection:
                    selection:
                        field|endswith:
                            - 'val1'
                            - 'val2'
                            - 'val3'
                    condition: selection
            """)
        ) == ['field EndsWithCIS "val1" OR field EndsWithCIS "val2" OR field EndsWithCIS "val3"']
