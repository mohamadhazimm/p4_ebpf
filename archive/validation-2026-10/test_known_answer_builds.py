import shutil
import subprocess

import pytest

from conftest import ROOT, unavailable


@pytest.mark.parametrize("build,flags", [("dynamic64", ["-m64"]),
                                       ("static64", ["-m64", "-static"]),
                                       ("compat32", ["-m32"])])
def test_b5_fixture_build_only(build, flags, tmp_path, request):
    compiler = shutil.which("cc")
    if not compiler:
        unavailable(request, "B5: C compiler missing")
    probe = subprocess.run([compiler, *flags, "-x", "c", "-", "-lresolv", "-o", str(tmp_path / "toolchain-probe")],
                           input="#include <arpa/inet.h>\nint main(void) { return 0; }\n",
                           capture_output=True, text=True, timeout=30)
    if probe.returncode:
        unavailable(request, f"B5: {build} toolchain unavailable: {probe.stderr[:600]}")
    result = subprocess.run([compiler, "-std=gnu11", "-Wall", "-Wextra", *flags,
                             str(ROOT / "tests/validation/known_answer.c"), "-lresolv", "-o", str(tmp_path / build)],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert (tmp_path / build).stat().st_size > 0