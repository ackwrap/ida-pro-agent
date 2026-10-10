"""SIMULATED in-memory RPC fixture metadata; excludes OS IPC/discovery/IDA."""
import json
from pathlib import Path
import tempfile


class MemoryIDA:
    def __init__(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ida-memory-")
        self.directory = Path(self.temp.name)
        self.arguments = ["-fixtures", str(Path(__file__).resolve().parents[1] / "protocol/testdata/valid")]
        self.trace = self.directory / "rpc.jsonl"
        self.stream = self.trace.open("a")
        self.gate = None

    def __enter__(self):
        return self

    @property
    def events(self):
        entries = []
        for line in self.trace.read_text().splitlines():
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            if entry.get("source") == "simulated_rpc":
                entries.append(entry)
        return entries

    @property
    def errors(self):
        return []

    @staticmethod
    def marker(instance):
        from mock_ida import A
        return "SIMULATED-A.i64" if instance == A else "SIMULATED-B.i64"

    def snapshot(self):
        return {"backend": "simulated_ida_inmemory_rpc", "events": self.events,
                "unverified": ["OS IPC", "registry discovery", "IDA APIs", "real IDB semantics"]}

    def __exit__(self, *_):
        self.stream.close()
        self.temp.cleanup()
