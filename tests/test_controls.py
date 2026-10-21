from pramana.controls import crosswalk_markdown, load_library
from pramana.registry import all_checks


def test_framework_catalogues_are_complete():
    lib = load_library()
    assert len(lib.frameworks["NIST"].controls) == 72
    assert len(lib.frameworks["ISO42001"].controls) == 38
    assert len(lib.frameworks["NIST-GAI"].controls) == 12
    assert len(lib.frameworks["OWASP-LLM"].controls) == 10
    sutras = [c for c in lib.frameworks["INDIA"].controls if c.id.startswith("SUTRA-")]
    assert len(sutras) == 7


def test_control_ids_are_unique_within_each_framework():
    lib = load_library()
    for fw in lib.frameworks.values():
        ids = [c.id for c in fw.controls]
        assert len(ids) == len(set(ids)), fw.id


def test_every_crosswalk_reference_resolves():
    assert load_library().validate() == []


def test_every_registered_check_is_in_the_crosswalk():
    lib = load_library()
    missing = [d.check_id for d in all_checks() if d.check_id not in lib.crosswalk]
    assert missing == []


def test_calendar_entries_have_sources():
    lib = load_library()
    for milestone in lib.calendar["milestones"]:
        assert milestone["source"].startswith("https://")


def test_crosswalk_markdown_mentions_each_check():
    text = crosswalk_markdown()
    for d in all_checks():
        assert f"`{d.check_id}`" in text
