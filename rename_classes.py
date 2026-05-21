import os
import re
from pathlib import Path

replacements = [
    (r"LConstReturnTest;", r"LConstReturnTest;"),
    (r"LFibonacciTest;", r"LFibonacciTest;"),
    (r"LFibonacciTest;", r"LFibonacciTest;"),
    (r"LBase;", r"LBase;"),
    (r"LMid;", r"LMid;"),
    (r"LMain;", r"LMain;"),
    (r"LIFoo;", r"LIFoo;"),
    (r"LCmdTest;", r"LCmdTest;"),
    (r"LTryCatchTest;", r"LTryCatchTest;"),
    (r"LLongArithmeticTest;", r"LLongArithmeticTest;"),
    (r"LPackedSwitchTest;", r"LPackedSwitchTest;"),
    (r"LBox;", r"LBox;"),
    (r"LInstanceFieldsTest;", r"LInstanceFieldsTest;"),
    (r"LArraysTest;", r"LArraysTest;"),
    (r"LInterfaceDispatchTest;", r"LInterfaceDispatchTest;"),
    (r"LTryCatchFieldsTest;", r"LTryCatchFieldsTest;"),
    # Lowercase references in comments?
    (r"\bp1\b", r"const_return"),
    (r"\bp2\b", r"fibonacci"),
    (r"\bp3\b", r"inheritance"),
]

for root, _, files in os.walk("."):
    if ".git" in root or ".gstack" in root or ".venv" in root or "__pycache__" in root or "egg-info" in root:
        continue
    for file in files:
        if not file.endswith(".py") and not file.endswith(".md"):
            continue
        filepath = Path(root) / file
        try:
            content = filepath.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
            
        new_content = content
        for old, new in replacements:
            new_content = re.sub(old, new, new_content)
        
        if content != new_content:
            filepath.write_text(new_content, encoding="utf-8")
            print(f"Updated {filepath}")
