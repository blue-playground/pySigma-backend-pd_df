import sys
import os

sys.path.append(os.getcwd() + "/sigma")

import pytest
from sigma.collection import SigmaCollection
from backends.pd_df import PandasDataFramePythonBackend


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
        == ["""df.query("fieldA=='valueA' and fieldB=='valueB'")"""]
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
        == ["""df.query("fieldA=='valueA' or fieldB=='valueB'")"""]
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
            """df.query("(fieldA==['valueA1','valueA2']) and (fieldB==['valueB1','valueB2'])",inplace=True)"""
        ]
    )

    # def test_pd_df_or_and_expression(pd_df_backend: PandasDataFramePythonBackend):
    #     assert (
    #         pd_df_backend.convert(
    #             SigmaCollection.from_yaml(
    #                 """
    #             title: Test
    #             status: test
    #             logsource:
    #                 category: test_category
    #                 product: test_product
    #             detection:
    #                 sel1:
    #                     fieldA: valueA1
    #                     fieldB: valueB1
    #                 sel2:
    #                     fieldA: valueA2
    #                     fieldB: valueB2
    #                 condition: 1 of sel*
    #         """
    #             )
    #         )
    #         == ["<insert expected result here>"]
    #     )

    # def test_pd_df_in_expression(pd_df_backend: PandasDataFramePythonBackend):
    #     assert (
    #         pd_df_backend.convert(
    #             SigmaCollection.from_yaml(
    #                 """
    #             title: Test
    #             status: test
    #             logsource:
    #                 category: test_category
    #                 product: test_product
    #             detection:
    #                 sel:
    #                     fieldA:
    #                         - valueA
    #                         - valueB
    #                         - valueC*
    #                 condition: sel
    #         """
    #             )
    #         )
    #         == ["<insert expected result here>"]
    #     )

    # def test_pd_df_regex_query(pd_df_backend: PandasDataFramePythonBackend):
    #     assert (
    #         pd_df_backend.convert(
    #             SigmaCollection.from_yaml(
    #                 """
    #             title: Test
    #             status: test
    #             logsource:
    #                 category: test_category
    #                 product: test_product
    #             detection:
    #                 sel:
    #                     fieldA|re: foo.*bar
    #                     fieldB: foo
    #                 condition: sel
    #         """
    #             )
    #         )
    #         == ["<insert expected result here>"]
    #     )

    # def test_pd_df_cidr_query(pd_df_backend: PandasDataFramePythonBackend):
    #     assert (
    #         pd_df_backend.convert(
    #             SigmaCollection.from_yaml(
    #                 """
    #             title: Test
    #             status: test
    #             logsource:
    #                 category: test_category
    #                 product: test_product
    #             detection:
    #                 sel:
    #                     field|cidr: 192.168.0.0/16
    #                 condition: sel
    #         """
    #             )
    #         )
    #         == ["<insert expected result here>"]
    #     )

    # def test_pd_df_field_name_with_whitespace(pd_df_backend: PandasDataFramePythonBackend):
    # assert (
    #     pd_df_backend.convert(
    #         SigmaCollection.from_yaml(
    #             """
    #         title: Test
    #         status: test
    #         logsource:
    #             category: test_category
    #             product: test_product
    #         detection:
    #             sel:
    #                 field name: value
    #             condition: sel
    #     """
    #         )
    #     )
    #     == ["<insert expected result here>"]
    # )


# TODOOODDD: implement tests for all backend features that don't belong to the base class defaults, e.g. features that were
# implemented with custom code, deferred expressions etc.
