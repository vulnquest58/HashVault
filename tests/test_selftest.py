from hashvault.analysis import discover_layers, is_terminal_hash
from hashvault.selftest import build_matrix_cases, run_crack_cases, run_matrix


def test_analysis_matrix_covers_every_operation():
    report = run_matrix()
    assert report.failed == 0, [
        (item.name, item.detail) for item in report.results if item.status != "pass"
    ]
    assert report.total_operations == len(report.covered_operations)
    assert report.missing_operations == []


def test_analysis_matrix_report_shape():
    report = run_matrix(include_archives=False)
    data = report.to_dict()
    assert data["summary"]["cases"] == len(build_matrix_cases())
    assert data["summary"]["operations_missing"] == ["ArchiveExtract"]
    assert data["summary"]["operations_failed"] == []
    assert len(data["operations"]) == report.total_operations
    coverage = {item["name"]: item for item in data["operations"]}
    assert coverage["Base64"]["covered"] is True
    assert coverage["Base64"]["passed"] >= 1
    assert coverage["ArchiveExtract"]["covered"] is False
    assert any(item["name"] == "Base64-wrapped MD5" for item in data["results"])


def test_operation_coverage_maps_cases_to_operations():
    report = run_matrix()
    coverage = {item.name: item for item in report.operation_coverage}
    assert len(coverage) == 54
    assert all(item.covered for item in coverage.values())
    assert all(not item.failures for item in coverage.values())
    assert "ArchiveExtract" in coverage
    assert coverage["Base64"].cases
    assert coverage["HashDetector"].cases


def test_near_miss_branches_are_bounded():
    discovery = discover_layers("NWY0ZGNjM2I1YWE3NjVkNjFkODMyN2RlYjg4MmNmOTk=")
    assert len(discovery.terminals) == 1
    assert len(discovery.traces) <= len(discovery.terminals) + 4


def test_structured_formats_are_terminal():
    vectors = [
        "4dd8965d1d476fa0d026722989a6b772:3060147285011",
        "u4-netntlm::kNS:338d08f8e26de93300000000000000000000000000000000:"
        "9526fb8c23a90751cdd619b6cea564742e1e4bf33006ba41:cb8086049ec4736c",
        "2582a8281bf9d4308d6f5731d0e61c61*4604ba734d4e*89acf0e761f4*"
        "ed487162465a774bfba60eb603a39f3a",
        "$postgres$postgres*f0784ea5*2091bb7d4725d1ca85e8de6ec349baf6",
        "$rar5$16$74575567518807622265582327032280$15$f8b4064de34ac02ecabfe9abdf93ed6a$8$9843834ed0f7c754",
        "$sntp-ms$7a4f8bd9c23e1094b5c8a2d1f3e0c7a4$0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d",
        "0x02003F3C9B86B4E5D1B9B2A9E5F3C8D7E6B5A4C3B2A1D0E9F8C7B6A5D4C3B2A1"
        "0F0E0D0C0B0A090807060504030201",
        "$sshng$6$16$3c4d5e6f7a8b9c0d1e2f3a4b$1232$3082...",
    ]
    assert all(is_terminal_hash(vector) for vector in vectors)


def test_cracking_matrix_builtin_handoff():
    results = run_crack_cases()
    assert {item.status for item in results} == {"pass"}
    assert all(item.actual == "password" for item in results)
    assert any(item.name.startswith("MD5") for item in results)
