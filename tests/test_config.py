import pytest

from ibr.config import Config, ConfigError, load_config


def test_defaults_are_usable():
    config = load_config()
    assert 1 <= config.max_hops <= 10
    assert config.max_paths_per_principal >= 1


@pytest.mark.parametrize("hops", [0, 11, -1])
def test_hop_limit_out_of_range_is_rejected(hops):
    with pytest.raises(ConfigError, match="max_hops"):
        Config(max_hops=hops)


def test_zero_paths_is_rejected():
    with pytest.raises(ConfigError, match="max_paths_per_principal"):
        Config(max_paths_per_principal=0)


def test_env_overrides_are_read(monkeypatch):
    monkeypatch.setenv("IBR_MAX_HOPS", "5")
    monkeypatch.setenv("IBR_MAX_PATHS", "50")
    config = load_config()
    assert config.max_hops == 5
    assert config.max_paths_per_principal == 50


def test_non_integer_env_is_rejected(monkeypatch):
    monkeypatch.setenv("IBR_MAX_HOPS", "lots")
    with pytest.raises(ConfigError, match="must be an integer"):
        load_config()


@pytest.mark.parametrize("raw, expected", [
    ("1", True), ("true", True), ("YES", True), ("on", True),
    ("0", False), ("false", False), ("no", False), ("", False),
])
def test_boolean_env_parsing(monkeypatch, raw, expected):
    monkeypatch.setenv("IBR_ASSUME_CONDITIONS", raw)
    assert load_config().assume_conditions_satisfiable is expected


def test_boolean_env_defaults_to_true_when_absent(monkeypatch):
    monkeypatch.delenv("IBR_ASSUME_CONDITIONS", raising=False)
    assert load_config().assume_conditions_satisfiable is True
