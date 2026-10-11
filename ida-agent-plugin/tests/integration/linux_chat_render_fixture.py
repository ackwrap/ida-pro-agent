"""Deterministic content for the real IDA rich-text/streaming regression."""
CPP_CODE = '''int answer() {
    const char *name = "return 0x10";
    /* block-comment
       still commented */
    return 42; // return 99;
}'''

PYTHON_CODE = '''def inspect(ea):
    doc = """for display
    still a string"""
    return int(ea) # recorded address'''

ASM_CODE = '''mov rax, 0x20 ; argument size
ldr x19, [x20, #0x10]
ret'''

JSON_CODE = '''{"label": "\u4e2d\u6587\U0001f916", "size": 42, "valid": true}'''

MARKDOWN = '''## Render check
Bold **evidence** and inline code `ida_database_info`.

- Inspect strings
- Compare callers

| Address | Meaning |
| --- | --- |
| 0x401000 | entry |

```cpp
int answer() {
    const char *name = "return 0x10";
    /* block-comment
       still commented */
    return 42; // return 99;
}
```

```cpp
/* isolated open comment
```

```cpp
return 31415;
```

```python
def inspect(ea):
    doc = """for display
    still a string"""
    return int(ea) # recorded address
```

```asm
mov rax, 0x20 ; argument size
ldr x19, [x20, #0x10]
ret
```

```json
{"label": "\u4e2d\u6587\U0001f916", "size": 42, "valid": true}
```

```
_DWORD check_size(_DWORD size) { return size; }
```

```text
return 31337
```

![remote](https://example.invalid/chat-test.png)
![local](file:///tmp/ida-chat-test.png)

<b>untrusted HTML</b>

render-markdown-complete
'''
BURST = "z" * 70000 + "\n" + "".join("burst-row-%04d: " % i + "x" * 1000 + "\n" for i in range(200)) + "burst-complete"

def seed_entries():
    return [{"speaker": "assistant", "text": "seed-%04d: history anchor\n\n" % i
        + ("Retained historical evidence. " * (70 if i >= 200 else 25)) + "\nsecond paragraph"} for i in range(400)]
