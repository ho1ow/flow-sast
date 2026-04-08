"""
phases/__init__.py
Sets up path so submodules in numbered dirs (1_catalog, 2_connect, etc.)
can be imported as phases.catalog, phases.connect, etc.
"""
import importlib
import sys
import types
from pathlib import Path


def _register_phase_aliases():
    """
    Register module aliases so:
      phases.catalog  → phases/1_catalog
      phases.connect  → phases/2_connect
      phases.verify   → phases/3_verify
      phases.analyze  → phases/4_analyze
      phases.confirm  → phases/5_confirm
      phases.shared   → phases/_shared
    """
    phases_dir = Path(__file__).parent
    alias_map = {
        "catalog": "1_catalog",
        "connect": "2_connect",
        "verify":  "3_verify",
        "analyze": "4_analyze",
        "confirm": "5_confirm",
        "shared":  "_shared",
    }

    for alias, real_name in alias_map.items():
        real_path = phases_dir / real_name
        if not real_path.exists():
            continue

        full_alias = f"phases.{alias}"
        if full_alias in sys.modules:
            continue

        # Create a package-like module pointing to the real directory
        spec = importlib.util.spec_from_file_location(
            full_alias,
            str(real_path / "__init__.py") if (real_path / "__init__.py").exists()
            else None,
            submodule_search_locations=[str(real_path)],
        )
        if spec is None:
            # Fallback: create empty namespace package
            mod = types.ModuleType(full_alias)
            mod.__path__ = [str(real_path)]
            mod.__package__ = full_alias
            sys.modules[full_alias] = mod
        else:
            mod = importlib.util.module_from_spec(spec)
            mod.__path__ = [str(real_path)]
            mod.__package__ = full_alias
            sys.modules[full_alias] = mod
            if spec.loader:
                try:
                    spec.loader.exec_module(mod)
                except Exception:
                    pass  # ignore init errors; submodule imports still work


_register_phase_aliases()
