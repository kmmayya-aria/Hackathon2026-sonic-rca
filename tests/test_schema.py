from sonic_rca.schema import (SCHEMA_VERSION, LAYERS, TECHSUPPORT_DBS,
                              DivergenceReport, Finding, Evidence)

def test_schema_constants():
    assert SCHEMA_VERSION == "0"
    assert LAYERS[0] == "CONFIG_DB" and LAYERS[-1] == "SAI"
    assert "APPL_STATE_DB" in TECHSUPPORT_DBS and len(TECHSUPPORT_DBS) == 7

def test_report_serializes():
    r = DivergenceReport(
        meta={"source": "dump", "sonic_version": "202605"},
        health={"services": [], "core_dumps": []},
        findings=[Finding(id="F-0001", check="vlan.membership",
                          object_type="VLAN_MEMBER", key="Vlan100|Ethernet4",
                          layer_expected="CONFIG_DB", layer_missing="APPL_DB",
                          expected={"tagging_mode": "untagged"}, observed=None,
                          severity="high", suspected_stage="vlanmgrd",
                          evidence=["ev:cfg:1"])],
        evidence={"ev:cfg:1": Evidence(id="ev:cfg:1",
                                       source="dump/CONFIG_DB.json",
                                       locator="VLAN_MEMBER|Vlan100|Ethernet4")},
    )
    assert '"F-0001"' in r.to_json()
