from sigma.conversion.state import ConversionState
from sigma.types import re, SigmaString, SigmaNumber
from sigma.rule import SigmaRule
from sigma.conversion.base import TextQueryBackend
from sigma.processing.pipeline import ProcessingPipeline
from sigma.pipelines.sentinelone import sentinelone_pipeline
from sigma.conversion.deferred import DeferredQueryExpression, DeferredTextQueryExpression
from sigma.conditions import ConditionFieldEqualsValueExpression, ConditionOR, ConditionAND, ConditionNOT, ConditionItem
from sigma.types import SigmaCompareExpression
from typing import Union, ClassVar, Optional, Tuple, List, Dict, Any, Pattern

class SentinelOneBackend(TextQueryBackend):
    """SentinelOne DeepVisibility query backend."""
    backend_processing_pipeline : ClassVar[ProcessingPipeline] = sentinelone_pipeline()

    # TODO: change the token definitions according to the syntax. Delete these not supported by your backend.
    # See the pySigma documentation for further infromation:
    # https://sigmahq-pysigma.readthedocs.io/en/latest/Backends.html
    # Operator precedence: tuple of Condition{AND,OR,NOT} in order of precedence.
    # The backend generates grouping if required
    name : ClassVar[str] = "SentinelOne Deep Visibility query backend"
    formats : Dict[str, str] = {
        "default": "Deep Visibiltiy queries",
    }
    
    requires_pipeline : bool = False            # TODO: does the backend requires that a processing pipeline is provided? This information can be used by user interface programs like Sigma CLI to warn users about inappropriate usage of the backend.
    precedence : ClassVar[Tuple[ConditionItem, ConditionItem, ConditionItem]] = (ConditionNOT, ConditionAND, ConditionOR)
    group_expression : ClassVar[str] = "({expr})"   # Expression for precedence override grouping as format string with {expr} placeholder
    #parenthesize: bool = True

    # Generated query tokens
    token_separator : str = " "     # separator inserted between all boolean operators
    or_token : ClassVar[str] = "OR"
    and_token : ClassVar[str] = "AND"
    not_token : ClassVar[str] = "NOT"
    eq_token : ClassVar[str] = "="  # Token inserted between field and value (without separator)

    # String output
    ## Fields
    ### Quoting
    field_quote : ClassVar[str] = '"'                               # Character used to quote field characters if field_quote_pattern matches (or not, depending on field_quote_pattern_negation). No field name quoting is done if not set.
    field_quote_pattern : ClassVar[Pattern] = re.compile("^\\w+$")   # Quote field names if this pattern (doesn't) matches, depending on field_quote_pattern_negation. Field name is always quoted if pattern is not set.
    field_quote_pattern_negation : ClassVar[bool] = True            # Negate field_quote_pattern result. Field name is quoted if pattern doesn't matches if set to True (default).

    ### Escaping
    #field_escape : ClassVar[str] = "\\"               # Character to escape particular parts defined in field_escape_pattern.
    #field_escape_quote : ClassVar[bool] = True        # Escape quote string defined in field_quote
    #field_escape_pattern : ClassVar[Pattern] = re.compile("[\\s*]")    # All matches of this pattern are prepended with the string contained in field_escape.

    ## Values
    str_quote       : ClassVar[str] = '"'     # string quoting character (added as escaping character)
    escape_char     : ClassVar[str] = "\\"    # Escaping character for special characrers inside string
    wildcard_multi  : ClassVar[str] = "*"     # Character used as multi-character wildcard
    wildcard_single : ClassVar[str] = "*"     # Character used as single-character wildcard
    add_escaped     : ClassVar[str] = "\\"    # Characters quoted in addition to wildcards and string quote
    filter_chars    : ClassVar[str] = ""      # Characters filtered
    bool_values     : ClassVar[Dict[bool, str]] = {   # Values to which boolean values are mapped.
        True: "true",
        False: "false",
    }

    # String matching operators. if none is appropriate eq_token is used.
    #startswith_expression : ClassVar[str] = "startswith"
    #endswith_expression   : ClassVar[str] = "endswith"
    contains_expression   : ClassVar[str] = "ContainsCIS"
    wildcard_match_expression : ClassVar[str] = "match"      # Special expression if wildcards can't be matched with the eq_token operator

    # Regular expressions
    re_expression : ClassVar[str] = "{field}=~{regex}"  # Regular expression query as format string with placeholders {field} and {regex}
    re_escape_char : ClassVar[str] = "\\"               # Character used for escaping in regular expressions
    re_escape : ClassVar[Tuple[str]] = ()               # List of strings that are escaped
    re_escape_escape_char : bool = True                 # If True, the escape character is also escaped
    # cidr expressions
    cidr_wildcard : ClassVar[str] = "*"    # Character used as single wildcard
    cidr_expression : ClassVar[str] = "cidrmatch({field}, {value})"    # CIDR expression query as format string with placeholders {field} = {value}
    cidr_in_list_expression : ClassVar[str] = "{field} in ({value})"    # CIDR expression query as format string with placeholders {field} = in({list})

    # Numeric comparison operators
    compare_op_expression : ClassVar[str] = "{field}{operator}{value}"  # Compare operation query as format string with placeholders {field}, {operator} and {value}
    # Mapping between CompareOperators elements and strings used as replacement for {operator} in compare_op_expression
    compare_operators : ClassVar[Dict[SigmaCompareExpression.CompareOperators, str]] = {
        SigmaCompareExpression.CompareOperators.LT  : "<",
        SigmaCompareExpression.CompareOperators.LTE : "<=",
        SigmaCompareExpression.CompareOperators.GT  : ">",
        SigmaCompareExpression.CompareOperators.GTE : ">=",
    }

    # Null/None expressions
    field_null_expression : ClassVar[str] = "{field} is null"          # Expression for field has null value as format string with {field} placeholder for field name

    # Field value in list, e.g. "field in (value list)" or "field containsall (value list)"
    convert_or_as_in : ClassVar[bool] = True                     # Convert OR as in-expression
    convert_and_as_in : ClassVar[bool] = True                    # Convert AND as in-expression
    in_expressions_allow_wildcards : ClassVar[bool] = True       # Values in list can contain wildcards. If set to False (default) only plain values are converted into in-expressions.
    field_in_list_expression : ClassVar[str] = "{field} {op} ({list})"  # Expression for field in list of values as format string with placeholders {field}, {op} and {list}
    or_in_operator : ClassVar[str] = "In"               # Operator used to convert OR into in-expressions. Must be set if convert_or_as_in is set
    and_in_operator : ClassVar[str] = "In"    # Operator used to convert AND into in-expressions. Must be set if convert_and_as_in is set
    list_separator : ClassVar[str] = ", "               # List element separator
    in_icontains_expression : ClassVar[Optional[str]] = "{field} In Contains Anycase ({list})"

    # Value not bound to a field
    unbound_value_str_expression : ClassVar[str] = '"{value}"'   # Expression for string value not bound to a field as format string with placeholder {value}
    unbound_value_num_expression : ClassVar[str] = '{value}'   # Expression for number value not bound to a field as format string with placeholder {value}
    unbound_value_re_expression : ClassVar[str] = '_=~{value}'    # Expression for regular expression not bound to a field as format string with placeholder {value}
  
    no_case_str_expression = "In Anycase ({value})"
  

    # TODO: implement custom methods for query elements not covered by the default backend base.
    # Documentation: https://sigmahq-pysigma.readthedocs.io/en/latest/Backends.html

    
    def convert_condition_field_eq_val_str(self, cond : ConditionFieldEqualsValueExpression, state : ConversionState) -> Union[str, DeferredQueryExpression]:
        """Conversion of field = string value expressions"""
        val = cond.value.to_plain()
        val_no_wc = val.rstrip(self.wildcard_multi).lstrip(self.wildcard_multi)

        # value uses `contains` modifier
        if val.startswith(self.wildcard_single) and val.endswith(self.wildcard_single):
            result = cond.field + self.token_separator + self.contains_expression + self.token_separator + self.field_quote + val_no_wc + self.field_quote
        # plain equals
        else:
            no_case_str = self.no_case_str_expression.format(value=self.convert_value_str(cond.value, state))
            result = cond.field + self.token_separator + no_case_str
            
        return result
    

    def convert_condition_as_in_expression(self, cond : Union[ConditionOR, ConditionAND], state : ConversionState) -> Union[str, DeferredQueryExpression]:
        """Conversion of field in value list conditions."""
        vals = [str(arg.value.to_plain() or "") for arg in cond.args]
        test_val = vals[0]
        vals_no_wc = [val.rstrip(self.wildcard_multi).lstrip(self.wildcard_multi) for val in vals]
        vals_no_wc = [val.rstrip(self.wildcard_multi).lstrip(self.wildcard_multi) for val in vals]
        vals_formatted = self.list_separator.join([self.field_quote + v + self.field_quote if isinstance(v, str) else str(v) for v in vals_no_wc])
        field=cond.args[0].field

        # or-in condition
        if isinstance(cond, ConditionOR):
            # contains-any
            if test_val.startswith(self.wildcard_single) and test_val.endswith(self.wildcard_single):
                result = self.in_icontains_expression.format(field=field, list=vals_formatted)
            # iin
            else:
                result = self.field_in_list_expression.format(field=field, list=vals_formatted)
        # contains-all
        else:
            result = self.in_icontains_expression.format(field=field, list=vals_formatted)

        return result