import shutil
import subprocess
from pathlib import Path

import pytest

from tres0r import docgen
from tres0r.cli import build_parser, main

ROOT = Path(__file__).resolve().parents[1]


def test_committed_files_are_current():
    """man/ und completions/ passen zum Code – sonst: python -m tres0r.docgen"""
    stale = [str(p.relative_to(ROOT)) for p, text in docgen.outputs(ROOT).items()
             if not p.exists() or p.read_text(encoding="utf-8") != text]
    assert not stale, f"veraltet: {stale} – bitte 'python -m tres0r.docgen' ausführen"


def test_every_command_is_documented_and_completable():
    page, bash, zsh = docgen.manpage(), docgen.bash_completion(), docgen.zsh_completion()
    for name, _, _ in docgen._commands(build_parser()):
        assert f'.SS "{docgen._roff(name)}"' in page, name
        last = name.split()[-1]
        assert last in bash and last in zsh, name
    assert page.isascii()


@pytest.mark.skipif(shutil.which("groff") is None, reason="groff fehlt")
def test_manpage_renders_without_warnings():
    run = subprocess.run(["groff", "-man", "-Tutf8", "-ww", "-z"], input=docgen.manpage().encode(),
                         capture_output=True)
    assert run.returncode == 0 and not run.stderr, run.stderr.decode()


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash fehlt")
def test_bash_completion_suggestions(tmp_path):
    script = tmp_path / "t.sh"
    (tmp_path / "Backup.tres0r").write_text("x")
    script.write_text(docgen.bash_completion() + '''
try() { COMP_WORDS=("$@"); COMP_CWORD=$((${#COMP_WORDS[@]} - 1)); COMPREPLY=(); _tres0r; echo "${COMPREPLY[*]}"; }
try tres0r pa; try tres0r keys add-sh; try tres0r pack --comp; try tres0r pack -l ""; try tres0r completion ""
try tres0r pack -o Back
''')
    out = subprocess.run(["bash", str(script)], capture_output=True, text=True, cwd=tmp_path).stdout.splitlines()
    assert out == ["pack passwd", "add-shares", "--compress", "schnell normal stark auto", "bash zsh",
                   "Backup.tres0r"]


@pytest.mark.skipif(shutil.which("zsh") is None, reason="zsh fehlt")
def test_zsh_completion_syntax(tmp_path):
    path = tmp_path / "_tres0r"
    path.write_text(docgen.zsh_completion())
    assert subprocess.run(["zsh", "-n", str(path)]).returncode == 0


def test_cli_prints_generated_texts(capsys):
    assert main(["completion", "bash"]) == 0
    assert capsys.readouterr().out == docgen.bash_completion()
    assert main(["manpage"]) == 0
    assert capsys.readouterr().out == docgen.manpage()


def test_every_public_parameter_is_documented():
    """Jeder Parameter einer öffentlichen Funktion steht im Docstring oder unter
    'Gemeinsame Parameter' (docgen.PARAMETERS)."""
    assert not docgen.undocumented()
