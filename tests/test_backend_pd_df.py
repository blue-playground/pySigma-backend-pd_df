import pytest
from sigma.collection import SigmaCollection
from sigma.backends.pd_df import PandasDataFramePythonBackend


@pytest.fixture
def pd_df_backend():
    return PandasDataFramePythonBackend()


# DONE: implement tests for some basic queries and their expected results.
def test_pd_df_and_expression(pd_df_backend: PandasDataFramePythonBackend):
    assert (
        pd_df_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: valueA
                    fieldB: valueB
                condition: sel
        """
            )
        )
        == ["""df.query("fieldA=='valueA' & fieldB=='valueB'")"""]
    )


def test_pd_df_or_expression(pd_df_backend: PandasDataFramePythonBackend):
    assert (
        pd_df_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA: valueA
                sel2:
                    fieldB: valueB
                condition: 1 of sel*
        """
            )
        )
        == ["""df.query("fieldA=='valueA' | fieldB=='valueB'")"""]
    )


def test_pd_df_and_or_expression(pd_df_backend: PandasDataFramePythonBackend):
    assert (
        pd_df_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - valueA1
                        - valueA2
                    fieldB:
                        - valueB1
                        - valueB2
                condition: sel
        """
            )
        )
        == [
            """df.query("(fieldA==['valueA1', 'valueA2']) & (fieldB==['valueB1', 'valueB2'])")"""
        ]
    )


def test_pd_df_or_and_expression(pd_df_backend: PandasDataFramePythonBackend):
    assert (
        pd_df_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA: valueA1
                    fieldB: valueB1
                sel2:
                    fieldA: valueA2
                    fieldB: valueB2
                condition: 1 of sel*
        """
            )
        )
        == [
            """df.query("fieldA=='valueA1' & fieldB=='valueB1' | fieldA=='valueA2' & fieldB=='valueB2'")"""
        ]
    )


def test_pd_df_in_expression(pd_df_backend: PandasDataFramePythonBackend):
    assert (
        pd_df_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - valueA
                        - valueB
                        - valueC*
                condition: sel
        """
            )
        )
        == [
            """df.query("fieldA=='valueA' | fieldA=='valueB' | fieldA.str.startswith('valueC')")"""
            ]
    )

def test_pd_df_regex_query(pd_df_backend: PandasDataFramePythonBackend):
    assert (
        pd_df_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|re: foo.*bar
                    fieldB: foo
                condition: sel
        """
            )
        )
        == ["""df.query("fieldA.str.contains('foo.*bar') & fieldB=='foo'")"""]
    )

def test_pd_df_cidr_query(pd_df_backend: PandasDataFramePythonBackend):
    assert (
        pd_df_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field|cidr: 192.168.0.0/16
                condition: sel
        """
            )
        )
        == ["""df.query("field.str.startswith('192.168.')")"""]
    )

def test_pd_df_field_name_with_whitespace(pd_df_backend: PandasDataFramePythonBackend):
    assert (
        pd_df_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field name: value
                condition: sel
        """
            )
        )
        == ["""df.query("`field name`=='value'")"""]
    )
