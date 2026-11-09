"""Environment and Dependency Verification Script.
Checks that all required libraries and directory structures are correctly set up.
"""

import sys
from pathlib import Path


def test_environment():
    print("=" * 60)
    print("ENVIRONMENT & DEPENDENCY VERIFICATION")
    print("=" * 60)

    # 1. Check Python version
    python_version = sys.version.split()[0]
    print(f"[+] Python Executable: {sys.executable}")
    print(f"[+] Python Version: {python_version}")
    assert sys.version_info >= (3, 8), "Python version must be >= 3.8"

    # 2. Check Core Dependencies
    modules = [
        ("numpy", "NumPy"),
        ("pandas", "Pandas"),
        ("sklearn", "Scikit-Learn"),
        ("streamlit", "Streamlit"),
        ("plotly", "Plotly"),
        ("matplotlib", "Matplotlib"),
        ("seaborn", "Seaborn"),
        ("joblib", "Joblib"),
        ("pytest", "Pytest"),
        ("sqlite3", "SQLite3 (Built-in)"),
    ]

    for mod_name, label in modules:
        try:
            mod = __import__(mod_name)
            ver = getattr(mod, "__version__", "built-in")
            print(f"[+] {label:20} : OK (v{ver})")
        except ImportError as e:
            print(f"[!] {label:20} : FAILED ({e})")
            raise

    # 3. Check Required Directories
    base_dir = Path(__file__).resolve().parent
    required_dirs = [
        base_dir / "data" / "raw",
        base_dir / "data" / "processed",
        base_dir / "models",
        base_dir / "reports",
        base_dir / "src",
        base_dir / "dashboard",
        base_dir / "tests",
    ]

    print("-" * 60)
    for p in required_dirs:
        rel = p.relative_to(base_dir)
        if p.exists() and p.is_dir():
            print(f"[+] Directory '{rel}' : EXISTS")
        else:
            print(f"[!] Directory '{rel}' : MISSING (Creating...)")
            p.mkdir(parents=True, exist_ok=True)

    print("=" * 60)
    print("ALL ENVIRONMENT CHECKS PASSED SUCCESSFULLY!")
    print("=" * 60)


if __name__ == "__main__":
    test_environment()
