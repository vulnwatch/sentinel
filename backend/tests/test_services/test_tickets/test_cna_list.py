"""Unit tests for the CNA list rules (backend/app/services/tickets/cna_list.py).

Owning specification: docs/features/tickets/cna.md (Fetcher:
`sync_mitre_cnas` — Algorithm step 3, CNA Entry Matching, Field Mapping,
Scope Plain Text, External String Admissibility; Testing Requirements,
item 7) and docs/conventions.md (External String Admissibility). The live
shapes are pinned by `test_cna_list_contract.py`; the fetcher that applies
these rules by `test_sync_mitre_cnas.py`. Every value is fictional.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from pydantic import MISSING

from app.services.tickets.cna_list import (
    CNAMetadata,
    InvalidScopeError,
    ListEntry,
    NamedCNA,
    map_fields,
    match_entries,
    parse_entry,
    scope_plain_text,
)
from tests.support.cve_program import entry_for
from tests.support.inadmissible import INADMISSIBLE_CHARACTERS, NUL, SURROGATE


def _row(short_name: str) -> NamedCNA:
    return NamedCNA(id=uuid.uuid7(), org_id=uuid.uuid4(), short_name=short_name)


def _entries(*short_names: str) -> list[ListEntry]:
    entries = [parse_entry(entry_for(name)) for name in short_names]
    assert all(entry is not None for entry in entries)
    return [entry for entry in entries if entry is not None]


def _pairs(rows: list[NamedCNA], entries: list[ListEntry]) -> list[tuple[int, int]]:
    """The matched pairs as `(row index, entry index)`."""
    matching = match_entries(rows, entries)
    return [
        (rows.index(row), next(i for i, e in enumerate(entries) if e is entry))
        for row, entry in matching.matched
    ]


def _ambiguous(rows: list[NamedCNA], entries: list[ListEntry]) -> list[int]:
    return [rows.index(row) for row in match_entries(rows, entries).ambiguous]


def _invalid_scope(value: str) -> InvalidScopeError:
    with pytest.raises(InvalidScopeError) as raised:
        scope_plain_text(value)
    return raised.value


# ---------------------------------------------------------------------------
# Entries (Algorithm, step 3)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestParseEntry:
    def test_valid_entry_keeps_its_trimmed_short_name_and_members(self) -> None:
        element = entry_for("  example \t")

        entry = parse_entry(element)

        assert entry is not None
        assert entry.short_name == "example"
        assert entry.members is element

    @pytest.mark.parametrize(
        "element",
        [
            pytest.param(None, id="null"),
            pytest.param("example", id="string"),
            pytest.param(1, id="number"),
            pytest.param(["example"], id="array"),
            pytest.param({}, id="no-short-name"),
            pytest.param({"shortName": None}, id="null-short-name"),
            pytest.param({"shortName": 1}, id="number-short-name"),
            pytest.param({"shortName": ["example"]}, id="array-short-name"),
            pytest.param({"shortName": ""}, id="empty-short-name"),
            pytest.param({"shortName": " \t\n"}, id="blank-short-name"),
        ],
    )
    def test_invalid_entry(self, element: Any) -> None:
        assert parse_entry(element) is None

    @pytest.mark.parametrize("character", INADMISSIBLE_CHARACTERS)
    def test_short_name_with_an_inadmissible_character_is_invalid(
        self, character: str
    ) -> None:
        assert parse_entry(entry_for(f"exa{character}mple")) is None

    def test_only_the_short_name_decides_validity(self) -> None:
        element = {"shortName": "example"}

        entry = parse_entry(element)

        assert entry is not None
        assert entry.short_name == "example"

    def test_equal_elements_are_two_entries(self) -> None:
        first, second = _entries("example", "example")

        assert first is not second
        assert first != second


# ---------------------------------------------------------------------------
# CNA Entry Matching
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestMatchEntries:
    def test_exact_short_name_matches(self) -> None:
        rows = [_row("example"), _row("other")]
        entries = _entries("other", "example")

        assert _pairs(rows, entries) == [(0, 1), (1, 0)]
        assert _ambiguous(rows, entries) == []

    def test_entry_short_name_is_compared_after_trimming(self) -> None:
        rows = [_row("example")]
        entries = _entries(" example ")

        assert _pairs(rows, entries) == [(0, 0)]

    def test_exact_candidate_is_preferred_over_case_folded_ones(self) -> None:
        rows = [_row("Snow"), _row("SNOW")]
        entries = _entries("Snow", "SNOW")

        assert _pairs(rows, entries) == [(0, 0), (1, 1)]
        assert _ambiguous(rows, entries) == []

    def test_case_folded_short_name_matches_when_there_is_no_exact_one(self) -> None:
        rows = [_row("example-vendor")]
        entries = _entries("Example-Vendor")

        assert _pairs(rows, entries) == [(0, 0)]

    def test_case_folding_is_unicode_case_folding(self) -> None:
        """`ß` folds to `ss`, which lowercasing alone does not do."""
        rows = [_row("STRASSE")]
        entries = _entries("straße")

        assert _pairs(rows, entries) == [(0, 0)]

    def test_two_case_folded_candidates_are_ambiguous(self) -> None:
        rows = [_row("snow")]
        entries = _entries("Snow", "SNOW")

        assert _pairs(rows, entries) == []
        assert _ambiguous(rows, entries) == [0]

    def test_exact_row_matches_while_a_case_folded_row_is_ambiguous(self) -> None:
        """`Snow` is the only candidate of the row `Snow`, and one of two
        candidates of the ambiguous row `snow`."""
        rows = [_row("snow"), _row("Snow")]
        entries = _entries("Snow", "SNOW")

        assert _pairs(rows, entries) == [(1, 0)]
        assert _ambiguous(rows, entries) == [0]

    def test_entry_shared_by_two_rows_matches_neither(self) -> None:
        rows = [_row("example"), _row("example")]
        entries = _entries("example")

        assert _pairs(rows, entries) == []
        assert _ambiguous(rows, entries) == [0, 1]

    def test_entry_that_is_the_only_candidate_of_an_exact_and_a_folded_row(
        self,
    ) -> None:
        rows = [_row("Example"), _row("example")]
        entries = _entries("Example")

        assert _pairs(rows, entries) == []
        assert _ambiguous(rows, entries) == [0, 1]

    def test_two_entries_with_one_short_name_are_ambiguous(self) -> None:
        rows = [_row("example")]
        entries = _entries("example", "example")

        assert _pairs(rows, entries) == []
        assert _ambiguous(rows, entries) == [0]

    def test_short_name_absent_from_the_list_is_neither_matched_nor_ambiguous(
        self,
    ) -> None:
        rows = [_row("ExampleMobile")]
        entries = _entries("Example_Mobile")

        matching = match_entries(rows, entries)

        assert matching.matched == ()
        assert matching.ambiguous == ()

    def test_no_looser_comparison_is_applied(self) -> None:
        rows = [_row("example"), _row("example-vendor")]
        entries = _entries("example ltd", "examplevendor")

        matching = match_entries(rows, entries)

        assert (matching.matched, matching.ambiguous) == ((), ())

    def test_results_follow_the_order_of_the_rows(self) -> None:
        rows = [_row("c"), _row("dup"), _row("a"), _row("dup"), _row("b")]
        entries = _entries("a", "b", "c", "dup")

        assert _pairs(rows, entries) == [(0, 2), (2, 0), (4, 1)]
        assert _ambiguous(rows, entries) == [1, 3]

    def test_empty_inputs(self) -> None:
        assert match_entries([], _entries("example")).matched == ()
        assert match_entries([_row("example")], []).matched == ()


# ---------------------------------------------------------------------------
# Field Mapping
# ---------------------------------------------------------------------------


def _mapped(**members: Any) -> CNAMetadata:
    element = entry_for("example")
    for key, value in members.items():
        if value is MISSING:
            element.pop(key, None)
        else:
            element[key] = value
    entry = parse_entry(element)
    assert entry is not None
    return map_fields(entry)


def _with_types(types: Any) -> CNAMetadata:
    element = entry_for("example", types=types)
    entry = parse_entry(element)
    assert entry is not None
    return map_fields(entry)


@pytest.mark.unit
class TestFieldMapping:
    def test_valid_fields_are_trimmed(self) -> None:
        metadata = _mapped(
            organizationName="  Example Corporation\n",
            CNA={"type": [" Vendor ", "Open Source"]},
            scope="  Example products.  ",
        )

        assert metadata == CNAMetadata(
            organization_name="Example Corporation",
            types=("Vendor", "Open Source"),
            scope="Example products.",
            invalid_fields=(),
        )

    def test_types_keep_list_order_and_duplicates_for_the_service(self) -> None:
        assert _with_types(["Vendor", "CERT", "Vendor"]).types == (
            "Vendor",
            "CERT",
            "Vendor",
        )

    def test_empty_types_are_valid(self) -> None:
        metadata = _with_types([])

        assert metadata.types == ()
        assert metadata.invalid_fields == ()

    @pytest.mark.parametrize(
        "value",
        [
            pytest.param(MISSING, id="absent"),
            pytest.param(None, id="null"),
            pytest.param(1, id="number"),
            pytest.param(["Example"], id="array"),
            pytest.param("", id="empty"),
            pytest.param("   ", id="blank"),
            pytest.param("x" * 257, id="257-characters"),
        ],
    )
    def test_invalid_organization_name(self, value: Any) -> None:
        metadata = _mapped(organizationName=value)

        assert metadata.organization_name is MISSING
        assert metadata.invalid_fields == ("organization_name",)

    def test_organization_name_bound_applies_to_the_trimmed_value(self) -> None:
        assert _mapped(organizationName=f" {'x' * 256} ").organization_name == (
            "x" * 256
        )

    @pytest.mark.parametrize(
        "cna",
        [
            pytest.param(MISSING, id="cna-absent"),
            pytest.param(None, id="cna-null"),
            pytest.param(["Vendor"], id="cna-array"),
            pytest.param({}, id="type-absent"),
            pytest.param({"type": None}, id="type-null"),
            pytest.param({"type": "Vendor"}, id="type-string"),
            pytest.param({"type": [f"t{i}" for i in range(17)]}, id="17-types"),
            pytest.param({"type": ["Vendor", 1]}, id="number-item"),
            pytest.param({"type": ["Vendor", None]}, id="null-item"),
            pytest.param({"type": [""]}, id="empty-item"),
            pytest.param({"type": [" "]}, id="blank-item"),
            pytest.param({"type": ["t" * 129]}, id="129-character-item"),
        ],
    )
    def test_invalid_types(self, cna: Any) -> None:
        metadata = _mapped(CNA=cna)

        assert metadata.types is MISSING
        assert metadata.invalid_fields == ("types",)

    def test_types_at_the_bounds_are_valid(self) -> None:
        sixteen = [f"t{i}" for i in range(15)] + [f" {'t' * 128} "]

        assert _with_types(sixteen).types == (*sixteen[:15], "t" * 128)

    @pytest.mark.parametrize(
        "value",
        [
            pytest.param(MISSING, id="absent"),
            pytest.param(None, id="null"),
            pytest.param(1, id="number"),
            pytest.param(["Example"], id="array"),
            pytest.param("Example <p>products</p>", id="not-convertible"),
        ],
    )
    def test_invalid_scope(self, value: Any) -> None:
        metadata = _mapped(scope=value)

        assert metadata.scope is MISSING
        assert metadata.invalid_fields == ("scope",)

    @pytest.mark.parametrize(
        "value", ["", "  ", "<strong></strong>", "<br/>"], ids=repr
    )
    def test_empty_converted_scope_is_valid_and_none(self, value: str) -> None:
        metadata = _mapped(scope=value)

        assert metadata.scope is None
        assert metadata.invalid_fields == ()

    def test_fields_are_validated_independently_and_named_in_column_order(
        self,
    ) -> None:
        metadata = _mapped(organizationName=None, CNA=None, scope="<p>")

        assert metadata == CNAMetadata(
            invalid_fields=("organization_name", "types", "scope")
        )

    def test_one_invalid_field_keeps_the_others_valid(self) -> None:
        metadata = _mapped(CNA={"type": "Vendor"})

        assert metadata.organization_name == "Example Corporation"
        assert metadata.scope == "Example Corporation products only."
        assert metadata.invalid_fields == ("types",)

    @pytest.mark.parametrize("character", INADMISSIBLE_CHARACTERS)
    @pytest.mark.parametrize(
        ("members", "field"),
        [
            pytest.param(
                lambda c: {"organizationName": f"Example{c}"},
                "organization_name",
                id="organization-name",
            ),
            pytest.param(
                lambda c: {"CNA": {"type": ["Vendor", f"Open{c}Source"]}},
                "types",
                id="type-item",
            ),
            pytest.param(lambda c: {"scope": f"Example{c}"}, "scope", id="scope"),
        ],
    )
    def test_inadmissible_character_makes_only_its_field_invalid(
        self, members: Any, field: str, character: str
    ) -> None:
        metadata = _mapped(**members(character))

        assert metadata.invalid_fields == (field,)
        assert getattr(metadata, field) is MISSING


# ---------------------------------------------------------------------------
# Scope Plain Text
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestScopePlainText:
    def test_specification_examples(self) -> None:
        assert scope_plain_text(
            "Projects listed on its <a href='https://github.com/example' "
            "target='_blank'>Example GitHub website</a> only."
        ) == (
            "Projects listed on its Example GitHub website "
            "(https://github.com/example) only."
        )
        assert scope_plain_text(
            "<strong>Root Scope:</strong> A.<br/><strong>CNA Scope:</strong> B &amp; C."
        ) == ("Root Scope: A.\nCNA Scope: B & C.")

    def test_text_is_kept_as_is_and_the_result_trimmed(self) -> None:
        assert scope_plain_text("  Example\tproducts,  only.\n") == (
            "Example\tproducts,  only."
        )

    @pytest.mark.parametrize("value", ["", " ", "\n\t", "<br>", "<strong> </strong>"])
    def test_empty_result_is_none(self, value: str) -> None:
        assert scope_plain_text(value) is None

    @pytest.mark.parametrize(
        "tag", ["<br>", "<br/>", "<br />", "</br>", "<BR>", "<br class='x'>"]
    )
    def test_each_br_tag_is_one_line_feed(self, tag: str) -> None:
        assert scope_plain_text(f"A.{tag}B.") == "A.\nB."

    def test_consecutive_br_tags_are_consecutive_line_feeds(self) -> None:
        assert scope_plain_text("A.<br/><br/>B.") == "A.\n\nB."

    @pytest.mark.parametrize(
        "value", ["<strong>A</strong>.", "<STRONG>A</STRONG>.", "<strong/>A."]
    )
    def test_strong_adds_nothing(self, value: str) -> None:
        assert scope_plain_text(value) == "A."

    def test_character_references_are_converted_and_stay_text(self) -> None:
        assert scope_plain_text(
            "A &amp; B &lt;script&gt; &quot;C&quot; &#39;D&#39; &#x45;"
        ) == ("A & B <script> \"C\" 'D' E")

    def test_unknown_or_incomplete_reference_is_text(self) -> None:
        assert scope_plain_text("A &unknown; B & C &am") == "A &unknown; B & C &am"

    def test_lone_less_than_sign_is_text(self) -> None:
        assert scope_plain_text("A < B, C <") == "A < B, C <"

    @pytest.mark.parametrize(
        "href",
        [
            "https://example.com/products",
            "http://example.com/products",
            "HTTPS://example.com/products",
            "https://example.com:8443/a?b=c#d",
        ],
    )
    def test_absolute_link_appends_its_url(self, href: str) -> None:
        assert scope_plain_text(f"<a href='{href}'>Products</a> only.") == (
            f"Products ({href}) only."
        )

    @pytest.mark.parametrize(
        "anchor",
        [
            pytest.param("<a href='/products'>Products</a>", id="relative-path"),
            pytest.param("<a href='products.html'>Products</a>", id="relative-file"),
            pytest.param("<a href='#top'>Products</a>", id="fragment"),
            pytest.param("<a href='//example.com/x'>Products</a>", id="no-scheme"),
            pytest.param("<a href='javascript:alert(1)'>Products</a>", id="js"),
            pytest.param("<a href='mailto:a@example.com'>Products</a>", id="mailto"),
            pytest.param("<a href='ftp://example.com/x'>Products</a>", id="ftp"),
            pytest.param("<a href='https:example.com'>Products</a>", id="no-host"),
            pytest.param("<a href='https://'>Products</a>", id="empty-host"),
            pytest.param(
                "<a href='https://example.com/a b'>Products</a>", id="whitespace"
            ),
            pytest.param("<a href='https://example.com/a\tb'>Products</a>", id="tab"),
            pytest.param("<a>Products</a>", id="no-href"),
            pytest.param("<a href>Products</a>", id="valueless-href"),
            pytest.param("<a href=''>Products</a>", id="empty-href"),
            pytest.param("<a href='https://[::1'>Products</a>", id="unparseable"),
        ],
    )
    def test_link_without_an_absolute_url_keeps_only_its_text(
        self, anchor: str
    ) -> None:
        assert scope_plain_text(f"{anchor} only.") == "Products only."

    def test_link_whose_trimmed_text_is_its_url_appends_nothing(self) -> None:
        assert scope_plain_text(
            "Listed on <a href='https://example.com/x'> https://example.com/x </a>."
        ) == ("Listed on  https://example.com/x .")

    def test_other_attributes_are_ignored_and_references_convert_in_href(
        self,
    ) -> None:
        assert scope_plain_text(
            "<a target='_blank' class='x' href='https://example.com/?a=1&amp;b=2'>"
            "Products</a>"
        ) == ("Products (https://example.com/?a=1&b=2)")

    def test_first_href_is_used(self) -> None:
        assert scope_plain_text(
            "<a href='https://example.com/first' href='https://example.com/second'>"
            "Products</a>"
        ) == ("Products (https://example.com/first)")

    def test_link_text_collects_its_text_br_and_strong(self) -> None:
        assert scope_plain_text(
            "<a href='https://example.com/x'><strong>Example</strong><br/>list</a>."
        ) == ("Example\nlist (https://example.com/x).")

    def test_self_closing_link_opens_a_link(self) -> None:
        """`<a/>` is the start tag `a` (HTML ignores the slash)."""
        assert scope_plain_text("<a/>Products</a> only.") == "Products only."

    @pytest.mark.parametrize(
        "value",
        [
            pytest.param("<a href='/x'>A <a href='/y'>B</a></a>", id="nested"),
            pytest.param("A <a href='/x'>B", id="unclosed"),
            pytest.param("A <a/> B", id="self-closing-unclosed"),
            pytest.param("A </a> B", id="end-without-start"),
        ],
    )
    def test_invalid_link_structure(self, value: str) -> None:
        _invalid_scope(value)

    @pytest.mark.parametrize(
        "value",
        [
            pytest.param("A <p>B</p>", id="p"),
            pytest.param("A </p> B", id="end-p"),
            pytest.param("A <em>B</em>", id="em"),
            pytest.param("A <script>B</script>", id="script"),
            pytest.param("A <style>B</style>", id="style"),
            pytest.param("A <img src='https://example.com/x.png'>", id="img"),
            pytest.param("A <div/>", id="self-closing-div"),
            pytest.param("A <!-- B -->", id="comment"),
            pytest.param("A </ B>", id="bogus-comment"),
            pytest.param("A <!B>", id="bogus-declaration"),
            pytest.param("<!DOCTYPE html>A", id="doctype"),
            pytest.param("A <![CDATA[B]]>", id="cdata"),
            pytest.param("A <?xml version='1.0'?>", id="processing-instruction"),
            pytest.param("A <!--", id="incomplete-comment"),
            pytest.param("A <?", id="incomplete-processing-instruction"),
        ],
    )
    def test_any_other_markup_is_invalid(self, value: str) -> None:
        _invalid_scope(value)

    @pytest.mark.parametrize(
        "value",
        [
            pytest.param("Example products <a", id="start-tag"),
            pytest.param("Example products <a href='https://example.com", id="attr"),
            pytest.param("Example products <br", id="br"),
            pytest.param("Example products <strong>only</stro", id="end-tag"),
            pytest.param("<a href='/x'>Products</a", id="link-end-tag"),
        ],
    )
    def test_incomplete_tag_at_the_end_is_invalid(self, value: str) -> None:
        """The parser would drop it without a trace (cna.md, Scope Plain
        Text)."""
        _invalid_scope(value)

    def test_length_bound_applies_to_the_trimmed_result(self) -> None:
        assert scope_plain_text(f"  {'x' * 4096}  ") == "x" * 4096
        assert scope_plain_text(f"<strong>{'x' * 4096}</strong>") == "x" * 4096
        _invalid_scope("x" * 4097)

    def test_appended_url_counts_toward_the_length_bound(self) -> None:
        href = "https://example.com/" + "p" * 20
        text = "x" * (4096 - len(href) - 3)

        assert scope_plain_text(f"<a href='{href}'>{text}</a>") == f"{text} ({href})"
        _invalid_scope(f"<a href='{href}'>{text}x</a>")

    @pytest.mark.parametrize("character", INADMISSIBLE_CHARACTERS)
    @pytest.mark.parametrize(
        "template",
        [
            pytest.param("Example{}products", id="text"),
            pytest.param("<a href='/x'>Exa{}mple</a>", id="link-text"),
            pytest.param("<a href='https://example.com/{}'>Example</a>", id="url"),
        ],
    )
    def test_inadmissible_character_in_the_result_is_invalid(
        self, template: str, character: str
    ) -> None:
        _invalid_scope(template.format(character))

    def test_inadmissible_character_in_a_dropped_href_is_not_stored(self) -> None:
        assert scope_plain_text(f"<a href='/x{NUL}'>Example</a>") == "Example"

    @pytest.mark.parametrize("reference", ["&#0;", "&#xD800;"])
    def test_reference_to_an_inadmissible_code_point_becomes_the_replacement(
        self, reference: str
    ) -> None:
        """HTML maps these references to U+FFFD, which is admissible."""
        assert scope_plain_text(f"A{reference}B") == "A\ufffdB"

    def test_error_message_is_fixed(self) -> None:
        error = _invalid_scope(f"Secret{SURROGATE} <p>value</p>")

        assert str(error) == "CNA scope is not convertible to plain text"
        assert isinstance(error, ValueError)
