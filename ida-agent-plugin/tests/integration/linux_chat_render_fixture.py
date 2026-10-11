"""Deterministic content for the real IDA rich-text/streaming regression."""
MARKDOWN = """## Render check
Bold **evidence** and inline code `ida_database_info`.

- Inspect strings
- Compare callers

| Address | Meaning |
| --- | --- |
| 0x401000 | entry |

``` cpp
int answer() {
    return 42;
}
```

![remote](https://example.invalid/chat-test.png)
![local](file:///tmp/ida-chat-test.png)

<b>untrusted HTML</b>

render-markdown-complete
"""
BURST = "z" * 70000 + "\n" + "".join("burst-row-%04d: " % i + "x" * 1000 + "\n" for i in range(200)) + "burst-complete"

def seed_entries():
    return [{"speaker": "assistant", "text": "seed-%04d: history anchor\n\n" % i
        + ("Retained historical evidence. " * (70 if i >= 200 else 25)) + "\nsecond paragraph"} for i in range(400)]
