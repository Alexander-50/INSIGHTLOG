# parser/plugin_manager.py
import importlib.util
import os

PLUGINS_DIR = os.path.join(os.path.dirname(__file__), "..", "plugins")
PLUGINS_DIR = os.path.abspath(PLUGINS_DIR)

def _load_module(path):
    spec = importlib.util.spec_from_file_location(os.path.basename(path), path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

class PluginManager:
    def __init__(self, plugins_dir=None):
        self.plugins_dir = plugins_dir or PLUGINS_DIR
        self.plugins = []
        self._discover()

    def _discover(self):
        if not os.path.isdir(self.plugins_dir):
            return
        for fname in os.listdir(self.plugins_dir):
            if fname.endswith(".py"):
                full = os.path.join(self.plugins_dir, fname)
                try:
                    mod = _load_module(full)
                    if hasattr(mod, "process_record"):
                        self.plugins.append(mod)
                except Exception as e:
                    print(f"[PLUGIN ERROR] Failed to load {fname}: {e}")

    def run_live(self, record):
        alerts = []
        for p in self.plugins:
            try:
                new = p.process_record(record)
                if new:
                    alerts.extend(new)
            except Exception as e:
                print(f"[PLUGIN ERROR] {p.__name__}: {e}")
        return alerts

    def run_batch(self, records):
        alerts = []
        for p in self.plugins:
            try:
                if hasattr(p, "evaluate_records"):
                    out = p.evaluate_records(records)
                    if out:
                        alerts.extend(out)
            except Exception as e:
                print(f"[PLUGIN ERROR] {p.__name__}: {e}")
        return alerts
