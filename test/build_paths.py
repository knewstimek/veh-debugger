"""Build output location shared by tests; VEH_TEST_BUILD_DIR selects another build (e.g. build32)."""
import os

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
BUILD_DIR = os.environ.get("VEH_TEST_BUILD_DIR", os.path.join(ROOT, "build"))
RELEASE = os.path.join(BUILD_DIR, "bin", "Release")
# An x86 tree ships only the 32-bit payload DLL.
IS_X86 = (os.path.exists(os.path.join(RELEASE, "vcruntime_net32.dll")) and
          not os.path.exists(os.path.join(RELEASE, "vcruntime_net.dll")))
ARCH = "x86" if IS_X86 else "x64"
CHALLENGES = os.path.join(ROOT, "test", "challenges")


def crackme(folder="crackme_v2"):
    """Crackme binary matching the build architecture."""
    return os.path.join(CHALLENGES, folder, f"crackme_{ARCH}.exe")
