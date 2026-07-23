"""YAML config yükleme ve profil çözümleme."""

import copy
import os

import yaml

_DEFAULT_PATH = os.path.join(os.path.dirname(__file__), "..", "config", "default.yaml")


def _deep_merge(base, override):
    """override sözlüğünü base üstüne özyinelemeli olarak birleştirir."""
    result = copy.deepcopy(base)
    for key, val in override.items():
        if isinstance(val, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], val)
        else:
            result[key] = copy.deepcopy(val)
    return result


def load_config(user_path=None):
    """Varsayılan config'i yükler, kullanıcı config'i verilmişse üstüne birleştirir."""
    with open(_DEFAULT_PATH, encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh)

    if user_path:
        with open(user_path, encoding="utf-8") as fh:
            user_cfg = yaml.safe_load(fh) or {}
        cfg = _deep_merge(cfg, user_cfg)

    return cfg


def resolve_profile(cfg, profile_name):
    """
    Seçilen profilin ayarlarını döndürür. Profil yoksa hata fırlatır.
    Dönüş: {modül_adı: {ayarlar}} sözlüğü.
    """
    profiles = cfg.get("profiles", {})
    if profile_name not in profiles:
        valid = ", ".join(profiles.keys())
        raise ValueError(f"Bilinmeyen profil '{profile_name}'. Geçerli: {valid}")
    return profiles[profile_name]
