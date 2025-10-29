from importlib.util import spec_from_file_location, module_from_spec
from pathlib import Path

MODULE_PATH = Path(__file__).parent / "app" / "main.py"
MODULE_NAME = "alert2snow_internal_main"

spec = spec_from_file_location(MODULE_NAME, MODULE_PATH)
if spec is None or spec.loader is None:
    raise ImportError(f"Unable to load application module from {MODULE_PATH}")
module = module_from_spec(spec)
spec.loader.exec_module(module)

app = module.app
