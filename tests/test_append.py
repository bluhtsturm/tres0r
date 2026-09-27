import io
import json
import os
import shutil

import pytest

from tres0r import container, keys, segments
from tres0r.cli import main
from tres0r.errors import FormatError, IntegrityError, Tres0rError
from tres0r.sign import SignatureError
from tres0r.mount import ContainerFS
from tres0r.progress import CancelToken, Monitor

from conftest import FAST, PASSWORD, snapshot


def pack(sources, out, **kw):
    return container.create(sources, out, PASSWORD, FAST, **kw).path


@pytest.fixture
def work(tmp_path):
    (tmp_path / "alt").mkdir()
    (tmp_path / "alt" / "notiz.txt").write_text("erste Fassung")
    (tmp_path / "alt" / "bild.bin").write_bytes(os.urandom(200_000))
    (tmp_path / "neu").mkdir()
    (tmp_path / "neu" / "notiz.txt").write_text("zweite Fassung, länger", encoding="utf-8")
    (tmp_path / "neu" / "extra.txt").write_text("extra")
    out = pack([tmp_path / "alt" / "notiz.txt", tmp_path / "alt" / "bild.bin"], tmp_path / "c.tres0r")
    return tmp_path, out


def add(out, *paths, **kw):
    return container.append(out, [str(p) for p in paths], PASSWORD, **kw)


def test_append_keeps_existing_bytes_and_newer_wins(work):
    tmp, out = work
    before = out.read_bytes()
    header_len = container.inspect(out).header_len
    result = add(out, tmp / "neu" / "notiz.txt", tmp / "neu" / "extra.txt")
    after = out.read_bytes()
    assert result.segment == 1 and result.entries == 2 and result.added == len(after) - len(before)
    assert after[header_len:len(before)] == before[header_len:]  # Bestand unberührt
    assert len(after[:header_len]) == header_len and after[:header_len] != before[:header_len]  # nur Flag + MAC
    assert container.inspect(out).segmented
    listing = {e.name: e.segment for e in container.list_contents(out, PASSWORD)}
    assert listing == {"bild.bin": 0, "notiz.txt": 1, "extra.txt": 1}
    checked = container.verify(out, PASSWORD)
    assert checked.segments == 2 and checked.files == 4
    container.extract(out, tmp / "z", PASSWORD)
    assert (tmp / "z" / "notiz.txt").read_text(encoding="utf-8") == "zweite Fassung, länger"
    assert sorted(os.listdir(tmp / "z")) == ["bild.bin", "extra.txt", "notiz.txt"]
    container.extract(out, tmp / "nur", PASSWORD, only=["notiz.txt"])
    assert (tmp / "nur" / "notiz.txt").read_text(encoding="utf-8") == "zweite Fassung, länger"
    fs = ContainerFS(out, PASSWORD)
    assert fs.open("/notiz.txt").read(0, 100) == b"zweite Fassung, l\xc3\xa4nger"
    fs.close()


def test_diff_and_type_change_across_segments(work):
    tmp, out = work
    ordner = tmp / "wechsel" / "notiz.txt"
    ordner.mkdir(parents=True)
    (ordner / "innen.txt").write_text("jetzt ein Ordner")
    add(out, ordner)
    container.extract(out, tmp / "z", PASSWORD)
    assert (tmp / "z" / "notiz.txt").is_dir() and (tmp / "z" / "notiz.txt" / "innen.txt").exists()
    assert container.diff(out, [tmp / "alt" / "bild.bin", ordner], PASSWORD).identical
    from tres0r import payload

    if payload.zstd_backend() is not None:
        compressed = add(out, tmp / "neu" / "extra.txt", compress=True)
        assert compressed.segment == 2 and container.verify(out, PASSWORD).segments == 3


def test_segment_signatures(work):
    tmp, out = work
    signer = keys.generate_signing_key()
    other = keys.generate_signing_key()
    signed = pack([tmp / "alt" / "notiz.txt"], tmp / "s.tres0r", sign_with=signer)
    add(signed, tmp / "neu" / "extra.txt", sign_with=signer)
    assert container.verify(signed, PASSWORD, signers=[signer.public_key()]).segments == 2
    add(signed, tmp / "neu" / "notiz.txt", sign_with=other)
    with pytest.raises(SignatureError):
        container.verify(signed, PASSWORD, signers=[signer.public_key()])
    assert container.verify(signed, PASSWORD, signers=[signer.public_key(), other.public_key()]).signer
    add(signed, tmp / "alt" / "bild.bin")  # unsigniertes Segment
    with pytest.raises(SignatureError):
        container.extract(signed, tmp / "z", PASSWORD, signers=[signer.public_key(), other.public_key()])
    assert not (tmp / "z").exists() or os.listdir(tmp / "z") == []
    container.verify(signed, PASSWORD)  # ohne Anforderung: in Ordnung


def test_truncation_to_older_state_is_detected(work):
    tmp, out = work
    original = out.stat().st_size
    add(out, tmp / "neu" / "notiz.txt")
    after_first = out.stat().st_size
    add(out, tmp / "neu" / "extra.txt")
    for size in (after_first, original):  # an alter Tabelle bzw. am Originalende abschneiden
        copy = tmp / f"kurz-{size}.tres0r"
        copy.write_bytes(out.read_bytes()[:size])
        with pytest.raises((FormatError, IntegrityError)):
            container.verify(copy, PASSWORD)


def test_table_tampering_and_transplant(work):
    tmp, out = work
    add(out, tmp / "neu" / "extra.txt")
    raw = bytearray(out.read_bytes())
    raw[-30] ^= 1
    broken = tmp / "t.tres0r"
    broken.write_bytes(bytes(raw))
    with pytest.raises(IntegrityError):
        container.verify(broken, PASSWORD)
    # Tabelle eines anderen Containers mit gleichem Schlüssel? AAD bindet an die Stream-Nonce
    table_len = int.from_bytes(out.read_bytes()[-12:-8], "big") + 16 + 12
    other = pack([tmp / "alt" / "notiz.txt"], tmp / "o.tres0r")
    add(other, tmp / "neu" / "extra.txt")
    mixed = tmp / "m.tres0r"
    mixed.write_bytes(out.read_bytes()[:-table_len] + other.read_bytes()[-table_len:])
    with pytest.raises((IntegrityError, FormatError)):
        container.verify(mixed, PASSWORD)


def test_cancelled_append_restores_original(work):
    tmp, out = work
    (tmp / "gross").mkdir()
    for i in range(5):
        (tmp / "gross" / f"{i}.bin").write_bytes(os.urandom(100_000))
    before = out.read_bytes()
    token = CancelToken()
    monitor = Monitor(lambda e: token.cancel() if e.phase == "packen" and e.item and e.item.endswith("2.bin")
                      else None, cancel=token, interval=0)
    from tres0r.errors import Cancelled
    with pytest.raises(Cancelled):
        container.append(out, [tmp / "gross"], PASSWORD, progress=monitor)
    assert out.read_bytes() == before and not segments.journal_path(out).exists()


def test_repair_after_power_loss_with_journal(work):
    tmp, out = work
    before = out.read_bytes()
    segments.write_journal(out, len(before), before[:container.inspect(out).header_len])
    with open(out, "ab") as f:
        f.write(os.urandom(70_000))  # halb geschriebenes Segment
    with pytest.raises(FormatError, match="repair"):
        container.verify(out, PASSWORD)
    assert container.inspect(out).interrupted
    result = container.repair(out, PASSWORD)
    assert "zurückgesetzt" in result.action and out.read_bytes() == before
    assert not segments.journal_path(out).exists()
    container.verify(out, PASSWORD)


def test_repair_completes_when_table_was_written(work):
    tmp, out = work
    header_len = container.inspect(out).header_len
    original_header = out.read_bytes()[:header_len]
    size = out.stat().st_size
    add(out, tmp / "neu" / "extra.txt")
    raw = bytearray(out.read_bytes())
    raw[:header_len] = original_header  # Absturz vor dem Umstellen des Headers
    out.write_bytes(bytes(raw))
    segments.write_journal(out, size, original_header)
    assert "abgeschlossen" in container.repair(out, PASSWORD).action
    assert container.verify(out, PASSWORD).segments == 2


def test_repair_without_journal_finds_last_table(work):
    tmp, out = work
    add(out, tmp / "neu" / "notiz.txt")
    good = out.read_bytes()
    with open(out, "ab") as f:
        f.write(os.urandom(50_000))  # zweites Anhängen abgebrochen, Journal verloren
    with pytest.raises(FormatError):
        container.verify(out, PASSWORD)
    assert "gekürzt" in container.repair(out, PASSWORD).action
    assert out.read_bytes() == good and container.verify(out, PASSWORD).segments == 2


def test_key_changes_after_append(work):
    tmp, out = work
    add(out, tmp / "neu" / "extra.txt")
    ident = keys.generate_identity()
    container.add_keys(out, PASSWORD, recipients=[ident.public_key()])  # Header wird länger
    assert container.verify(out, keys.Credentials(identities=[ident])).segments == 2
    container.change_password(out, PASSWORD, "neu")
    assert {e.name for e in container.list_contents(out, "neu")} == {"notiz.txt", "bild.bin", "extra.txt"}


def test_salvage_segmented(work):
    tmp, out = work
    add(out, tmp / "neu" / "extra.txt")
    raw = bytearray(out.read_bytes())
    raw[-30] ^= 1  # Tabelle kaputt
    out.write_bytes(bytes(raw))
    result = container.salvage(out, tmp / "rettung", PASSWORD)
    assert any("Segmenttabelle" in n for n in result.notes)
    assert (tmp / "rettung" / "bild.bin").read_bytes() == (tmp / "alt" / "bild.bin").read_bytes()


def test_append_refusals(work, tmp_path):
    tmp, out = work
    split = pack([tmp / "alt"], tmp / "teile.tres0r", split=1 << 20)
    with pytest.raises(Tres0rError, match="aufgeteilte"):
        add(split, tmp / "neu")
    raw = tmp / "roh.tres0r"
    with container.atomic_output(raw) as f:
        container.encrypt_stream(io.BytesIO(b"x"), f, PASSWORD, FAST)
    with pytest.raises(Tres0rError, match="Rohdaten"):
        add(raw, tmp / "neu")
    add(out, tmp / "neu" / "extra.txt")
    with pytest.raises(Tres0rError, match="Pipe"):
        container.extract_stream(io.BytesIO(out.read_bytes()), tmp / "p", PASSWORD)
    segments.write_journal(out, out.stat().st_size - 10, None)
    with open(out, "ab") as f:
        f.write(b"x")
    with pytest.raises(FormatError, match="repair"):
        add(out, tmp / "neu" / "notiz.txt")


def test_cli_append_repair_info(work, capsys):
    tmp, out = work
    pw = tmp / "pw"
    pw.write_text(PASSWORD + "\n")
    assert main(["append", str(out), str(tmp / "neu"), "--password-file", str(pw)]) == 0
    capsys.readouterr()
    assert main(["info", str(out), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["segmented"] is True
    assert main(["verify", str(out), "--password-file", str(pw), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["segments"] == 2
    shutil.copy(out, tmp / "kopie.tres0r")
    assert main(["repair", str(tmp / "kopie.tres0r"), "--password-file", str(pw), "--json"]) == 0
    assert "in Ordnung" in json.loads(capsys.readouterr().out)["action"]
    assert snapshot(tmp / "neu") == snapshot(tmp / "neu")
