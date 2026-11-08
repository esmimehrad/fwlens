import pytest

from fwlens.parsers.fortigate import build_tree, tokenize


def tokens(text: str) -> list[tuple[str, ...]]:
    return [s.tokens for s in tokenize(text)]


# --- tokenizer --------------------------------------------------------------


def test_quoted_values_keep_spaces() -> None:
    assert tokens('set comments "two words"') == [("set", "comments", "two words")]


def test_escaped_quotes_are_unescaped() -> None:
    assert tokens(r'set comments "say \"hi\""') == [("set", "comments", 'say "hi"')]


def test_multiple_values_on_one_line() -> None:
    assert tokens('set member "h1" "h2" h3') == [("set", "member", "h1", "h2", "h3")]


def test_comment_lines_and_blank_lines_are_skipped() -> None:
    assert tokens("#config-version=FGT60F\n\n  end  \n") == [("end",)]


def test_multi_line_quoted_value_keeps_line_numbers() -> None:
    statements = list(tokenize('set comments "line one\nline two"\nnext'))
    assert statements[0].tokens == ("set", "comments", "line one\nline two")
    assert statements[1].line == 3


# --- tree builder ------------------------------------------------------------


def test_nested_config_edit_set() -> None:
    root = build_tree(
        """
        config firewall address
            edit "h1"
                set subnet 10.0.0.1 255.255.255.255
            next
            edit "h2"
                set type fqdn
                set fqdn "a.example.com"
            next
        end
        """
    )
    addresses = root.blocks["firewall address"]
    assert list(addresses.entries) == ["h1", "h2"]
    assert addresses.entries["h1"].settings["subnet"] == ("10.0.0.1", "255.255.255.255")
    assert addresses.entries["h2"].value("fqdn") == "a.example.com"


def test_config_inside_edit() -> None:
    root = build_tree(
        """
        config system interface
            edit "port1"
                config ipv6
                    set ip6-mode static
                end
                set alias "lan"
            next
        end
        """
    )
    port1 = root.blocks["system interface"].entries["port1"]
    assert port1.blocks["ipv6"].value("ip6-mode") == "static"
    assert port1.value("alias") == "lan"


def test_unset_removes_a_setting() -> None:
    root = build_tree("config system global\nset hostname x\nunset hostname\nend")
    assert root.blocks["system global"].value("hostname") is None


def test_value_default() -> None:
    root = build_tree("config firewall policy\nedit 1\nnext\nend")
    assert root.blocks["firewall policy"].entries["1"].value("action", "deny") == "deny"


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("config a\nnext", "line 2: 'next' without matching 'edit'"),
        ("config a\nedit 1\nend", "line 3: 'end' without matching 'config'"),
        ("config a\nedit 1\nnext", "unterminated 'config'"),
        ("config a\nappend x y\nend", "line 2: unknown statement 'append'"),
    ],
)
def test_malformed_structure_raises(text: str, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        build_tree(text)
