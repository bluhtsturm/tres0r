import io
import os

import pytest

from tres0r import container, keys, volumes
from tres0r.errors import FormatError, IntegrityError, Tres0rError

from conftest import FAST, PASSWORD, snapshot

MIB = 1 << 20


def pack(sources, out, **kw):
    return container.create(sources, out, PASSWORD, FAST, **kw)


@pytest.fixture
def big(tmp_path):
    root = tmp_path / "quelle" / "Daten"
    root.mkdir(parents=True)
    for i in range(3):
        (root / f"teil{i}.bin").write_bytes(os.urandom(1_300_000))
    (root / "klein.txt").write_text("klein")
    return root


def parts(tmp_path, name="s.tres0r"):
    return sorted(p.name for p in tmp_path.iterdir() if p.name.startswith(name))


def test_parse_size():
    assert volumes.parse_size("4G") == 4 << 30 and volumes.parse_size("700M") == 700 << 20
    assert volumes.parse_size("650MB") == 650_000_000 and volumes.parse_size("1,5GiB") == int(1.5 * (1 << 30))
    for bad in ("12", "4X", "", "1K"):
        with pytest.raises(Tres0rError):
            volumes.parse_size(bad)


def test_container_name_ending_in_digits_is_not_a_part(tmp_path, big):
    """Fund: "Steuer.2024" galt als Teil 2024 eines Satzes – create schrieb die Datei
    und meldete dann "Teil 1 fehlt", kein Befehl konnte den Container öffnen."""
    out = tmp_path / "Steuer.2024"
    result = pack([big], out)
    assert result.size == out.stat().st_size and volumes.base_of(out) is None
    assert container.inspect(out).volumes == 1
    assert len(container.list_contents(out, PASSWORD)) == 5
    container.append(out, [tmp_path / "quelle" / "Daten" / "klein.txt"], PASSWORD)
    container.verify(out, PASSWORD)
    # Ein echter späterer Teil beginnt nicht mit der Kennung: weiterhin "Teil 1 fehlt"
    pack([big], tmp_path / "s.tres0r", split=MIB)
    (tmp_path / "s.tres0r.001").unlink()
    with pytest.raises(FormatError, match="Teil 1"):
        container.inspect(tmp_path / "s.tres0r.002")


def test_split_roundtrip_and_random_access(tmp_path, big):
    result = pack([big], tmp_path / "s.tres0r", split=MIB)
    names = parts(tmp_path)
    assert names == [f"s.tres0r.{i:03d}" for i in range(1, len(names) + 1)] and len(names) >= 4
    assert all((tmp_path / n).stat().st_size == MIB for n in names[:-1])
    assert result.size == sum((tmp_path / n).stat().st_size for n in names)
    for handle in (tmp_path / "s.tres0r", tmp_path / "s.tres0r.001", tmp_path / names[-1]):
        info = container.inspect(handle)
        assert info.volumes == len(names) and info.size == result.size
    assert container.verify(tmp_path / "s.tres0r", PASSWORD).files == 4
    container.extract(tmp_path / "s.tres0r", tmp_path / "z", PASSWORD, only=["Daten/teil2.bin"])
    assert (tmp_path / "z/Daten/teil2.bin").read_bytes() == (big / "teil2.bin").read_bytes()
    container.extract(tmp_path / "s.tres0r.001", tmp_path / "alles", PASSWORD)
    assert snapshot(tmp_path / "alles/Daten") == snapshot(big)
    assert container.diff(tmp_path / "s.tres0r", [big], PASSWORD).identical
    concatenated = b"".join((tmp_path / n).read_bytes() for n in names)
    container.extract_stream(io.BytesIO(concatenated), tmp_path / "pipe", PASSWORD)
    assert snapshot(tmp_path / "pipe/Daten") == snapshot(big)


def test_missing_or_truncated_parts(tmp_path, big):
    pack([big], tmp_path / "s.tres0r", split=MIB)
    third = tmp_path / "s.tres0r.003"
    saved = third.read_bytes()
    third.unlink()
    with pytest.raises(FormatError, match="Teil 3"):
        container.verify(tmp_path / "s.tres0r", PASSWORD)
    third.write_bytes(saved)
    last = tmp_path / parts(tmp_path)[-1]
    last.write_bytes(last.read_bytes()[:-100])
    with pytest.raises(IntegrityError):
        container.verify(tmp_path / "s.tres0r", PASSWORD)
    result = container.salvage(tmp_path / "s.tres0r", tmp_path / "rettung", PASSWORD)
    assert len(result.recovered) >= 3  # vor der Beschädigung ist alles da


def test_key_changes_keep_split(tmp_path, big):
    pack([big], tmp_path / "s.tres0r", split=MIB)
    before = parts(tmp_path)
    container.add_keys(tmp_path / "s.tres0r", PASSWORD, recipients=[keys.generate_identity().public_key()])
    container.change_password(tmp_path / "s.tres0r.001", PASSWORD, "neu")
    assert parts(tmp_path) == before
    assert container.verify(tmp_path / "s.tres0r", "neu").files == 4
    assert [n for n in os.listdir(tmp_path) if n.startswith(".")] == []


def test_switching_between_split_and_single(tmp_path, big):
    out = tmp_path / "s.tres0r"
    pack([big], out, split=MIB)
    with pytest.raises(Tres0rError, match="existiert bereits"):
        pack([big], out)
    pack([big], out, overwrite=True)  # einzeln: alte Teile verschwinden
    assert parts(tmp_path) == ["s.tres0r"]
    pack([big], out, overwrite=True, split=2 * MIB)  # wieder aufgeteilt: Einzeldatei verschwindet
    assert "s.tres0r" not in parts(tmp_path) and parts(tmp_path)[0] == "s.tres0r.001"
    container.verify(out, PASSWORD)


def test_split_output_inside_source_is_not_packed(tmp_path, big):
    out = big / "selbst.tres0r"
    pack([big], out, split=MIB)
    pack([big], out, split=MIB, overwrite=True)  # jetzt liegen alte Teile im Quellordner
    names = {e.name for e in container.list_contents(out, PASSWORD)}
    assert not any("selbst.tres0r" in n for n in names)


def test_split_raw_stream_and_upgrade(tmp_path):
    data = os.urandom(3 * MIB)
    with container.atomic_output(tmp_path / "r.tres0r", split=MIB) as f:
        container.encrypt_stream(io.BytesIO(data), f, PASSWORD, FAST)
    assert len(parts(tmp_path, "r.tres0r")) == 4
    source, size = volumes.open_read(tmp_path / "r.tres0r")
    out = io.BytesIO()
    with source:
        container.decrypt_stream(source, out, PASSWORD, total=size)
    assert out.getvalue() == data


def test_failed_split_write_leaves_nothing(tmp_path):
    with pytest.raises(RuntimeError):
        with container.atomic_output(tmp_path / "x.tres0r", split=MIB) as f:
            f.write(os.urandom(3 * MIB))
            raise RuntimeError("abbruch")
    assert os.listdir(tmp_path) == []
