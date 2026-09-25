"""Build output location shared by tests; VEH_TEST_BUILD_DIR selects another build (e.g. build32)."""
import os

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
BUILD_DIR = os.environ.get("VEH_TEST_BUILD_DIR", os.path.join(ROOT, "build"))
RELEASE = os.path.join(BUILD_DIR, "bin", "Release")
