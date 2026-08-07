from argus.collectors import Component, _extract_version, collect_system_info


def test_extract_version_simple():
    assert _extract_version("sudo 1.9.15") == "1.9.15"


def test_extract_version_with_build_metadata():
    assert _extract_version("OpenSSL 3.0.13-1ubuntu3") == "3.0.13-1ubuntu3"


def test_extract_version_none_when_absent():
    assert _extract_version("no version here") is None
    assert _extract_version(None) is None


def test_collect_system_info_returns_kernel_and_arch():
    info = collect_system_info()
    assert info.kernel_version
    assert info.arch
    assert isinstance(info.components, list)


def test_component_dataclass_defaults():
    c = Component(name="sudo", version="1.9.15", source="binary")
    assert c.raw == ""
