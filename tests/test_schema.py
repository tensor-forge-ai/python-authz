import pytest

from authz.schema import (
    Direct,
    Exclusion,
    From,
    Intersection,
    Namespace,
    TupleToUserset,
    Union,
    build_role_hierarchy,
)


def test_direct_repr():
    assert repr(Direct()) == "Direct()"


def test_union_holds_children_in_order():
    d, f = Direct(), From("owner")
    u = Union(d, f)
    assert u.children == (d, f)


def test_intersection_holds_children_in_order():
    d, f = Direct(), From("compliance_cleared")
    i = Intersection(d, f)
    assert i.children == (d, f)


def test_exclusion_holds_base_and_subtract():
    base, subtract = Direct(), From("banned")
    e = Exclusion(base, subtract)
    assert e.base is base
    assert e.subtract is subtract


def test_from_holds_relation_name():
    assert From("owner").relation == "owner"


def test_tuple_to_userset_holds_relation_names():
    t2u = TupleToUserset("parent", "viewer")
    assert t2u.tupleset_relation == "parent"
    assert t2u.computed_relation == "viewer"


def test_namespace_holds_name_and_relations():
    relations = {
        "owner": Direct(),
        "editor": Union(Direct(), From("owner")),
    }
    ns = Namespace("document", relations)
    assert ns.name == "document"
    assert ns.relations == relations
    assert ns.singleton_relations == frozenset()
    assert ns.max_subjects == {}
    assert ns.max_subjects_for("owner") is None


def test_namespace_singleton_and_max_subjects():
    relations = {
        "org_admin": Direct(),
        "manager": Direct(),
        "member": Direct(),
    }
    ns = Namespace(
        "org",
        relations,
        singleton_relations={"org_admin"},
        max_subjects={"manager": 3},
    )
    assert ns.singleton_relations == frozenset({"org_admin"})
    assert ns.max_subjects == {"manager": 3}
    assert ns.max_subjects_for("org_admin") == 1
    assert ns.max_subjects_for("manager") == 3
    assert ns.max_subjects_for("member") is None


def test_build_role_hierarchy():
    roles = ["org_admin", "org_manager", "tpa_coordinator", "org_user", "diagnostic_billing_staff"]
    extra = {"custom_perm": Direct()}
    rel_map = build_role_hierarchy(roles, extra_relations=extra)

    # Top role
    assert isinstance(rel_map["org_admin"], Direct)
    assert isinstance(rel_map["override_org_admin"], From)
    assert rel_map["override_org_admin"].relation == "org_admin"

    # Second role
    assert isinstance(rel_map["org_manager"], Union)
    assert isinstance(rel_map["org_manager"].children[0], Direct)
    assert isinstance(rel_map["org_manager"].children[1], From)
    assert rel_map["org_manager"].children[1].relation == "org_admin"
    assert isinstance(rel_map["override_org_manager"], From)
    assert rel_map["override_org_manager"].relation == "org_admin"

    # Fifth role
    assert isinstance(rel_map["diagnostic_billing_staff"], Union)
    assert rel_map["diagnostic_billing_staff"].children[1].relation == "org_user"
    assert rel_map["override_diagnostic_billing_staff"].relation == "org_user"

    # Extra relations preserved
    assert "custom_perm" in rel_map
    assert isinstance(rel_map["custom_perm"], Direct)


def test_build_role_hierarchy_duplicate_roles_raises():
    import pytest

    with pytest.raises(ValueError, match="duplicate"):
        build_role_hierarchy(["admin", "manager", "admin"])


def test_namespace_copies_relations_so_later_mutation_has_no_effect():
    relations = {"owner": Direct()}
    ns = Namespace("document", relations)
    relations["viewer"] = From("editor")
    relations["editor"] = From("viewer")
    assert set(ns.relations) == {"owner"}


def test_namespace_relations_are_read_only():
    ns = Namespace("document", {"owner": Direct()})
    with pytest.raises(TypeError):
        ns.relations["viewer"] = Direct()  # type: ignore[index]
    with pytest.raises(TypeError):
        del ns.relations["owner"]  # type: ignore[attr-defined]
    with pytest.raises(TypeError):
        ns.max_subjects["owner"] = 5  # type: ignore[index]


def test_mutating_the_source_mapping_after_register_cannot_bypass_cycle_check(client):
    relations = {"viewer": Direct(), "editor": Direct()}
    client.register_schema(Namespace("document", relations))
    relations["viewer"] = From("editor")
    relations["editor"] = From("viewer")
    assert isinstance(client.schema["document"].relations["viewer"], Direct)
