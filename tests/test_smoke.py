"""Smoke tests for basic imports."""
import os
import sys


def test_repo_structure():
    """Basic repo structure checks."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    assert os.path.exists(os.path.join(root, "README.md"))
    assert os.path.exists(os.path.join(root, "requirements.txt"))
    assert os.path.exists(os.path.join(root, "step1_load_clean.py"))
    assert os.path.exists(os.path.join(root, "step2_baseline.py"))
    assert os.path.exists(os.path.join(root, "step3_alerts.py"))
    assert os.path.exists(os.path.join(root, "step4_assistant.py"))
    assert os.path.exists(os.path.join(root, "step5_hard_eval.py"))
    assert os.path.exists(os.path.join(root, "step6_demo_page.py"))


def test_python_files_compile():
    """Check all Python files compile."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for fname in os.listdir(root):
        if fname.endswith(".py"):
            path = os.path.join(root, fname)
            with open(path, "r", encoding="utf-8") as f:
                compile(f.read(), path, "exec")
