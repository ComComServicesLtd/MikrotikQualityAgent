#!/usr/bin/env python3
"""Convert an OCI-layout image archive into a legacy Docker archive.

RouterOS's container importer only understands the *legacy* Docker archive
layout, where each layer lives at ``<layer-id>/layer.tar`` and is stored
uncompressed. Docker's containerd image store emits the OCI layout instead --
``blobs/sha256/<digest>``, with gzipped layers -- and it does so even for
``docker save`` and ``docker buildx build --output=type=docker``.

Feeding an OCI-layout archive to ``/container/add`` fails with:

    download/extract error: could not load next layer

which names neither the real cause nor the fix. Hence this script.

Usage:
    oci-to-docker-archive.py <input.tar> <output.tar> [repo:tag]
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path


def die(msg: str) -> None:
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(1)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def convert(src: Path, dst: Path, repo_tag: str | None) -> None:
    with tempfile.TemporaryDirectory(prefix="oci2docker-") as tmp:
        work = Path(tmp)
        extracted = work / "in"
        extracted.mkdir()

        with tarfile.open(src) as tf:
            # filter="data" refuses absolute paths and traversal. These archives
            # are locally produced, but the guard costs nothing.
            try:
                tf.extractall(extracted, filter="data")
            except TypeError:  # Python < 3.12
                tf.extractall(extracted)

        manifest_path = extracted / "manifest.json"
        if not manifest_path.exists():
            die(f"{src} has no manifest.json — is it a container image archive?")

        manifest = json.loads(manifest_path.read_text())
        if not manifest:
            die("manifest.json is empty")
        entry = manifest[0]

        config_rel = entry["Config"]
        layers_rel = entry["Layers"]
        tags = repo_tag.split(",") if repo_tag else entry.get("RepoTags") or []

        if not config_rel.startswith("blobs/"):
            print(f"{src} is already in the legacy layout; copying unchanged")
            shutil.copy2(src, dst)
            return

        config_src = extracted / config_rel
        config = json.loads(config_src.read_text())
        diff_ids = config.get("rootfs", {}).get("diff_ids", [])
        if len(diff_ids) != len(layers_rel):
            die(f"config lists {len(diff_ids)} diff_ids but manifest lists {len(layers_rel)} layers")

        out = work / "out"
        out.mkdir()

        # The config file is named by its own digest, as docker save does.
        config_digest = sha256_file(config_src)
        config_name = f"{config_digest}.json"
        shutil.copy2(config_src, out / config_name)

        created = config.get("created", "1970-01-01T00:00:00Z")
        legacy_layers = []
        parent = None

        for idx, (layer_rel, diff_id) in enumerate(zip(layers_rel, diff_ids)):
            blob = extracted / layer_rel

            # Layer IDs in the legacy format are opaque; derive them from the
            # diff_id so the output is byte-for-byte reproducible across runs.
            layer_id = hashlib.sha256(f"{diff_id}:{idx}".encode()).hexdigest()
            layer_dir = out / layer_id
            layer_dir.mkdir()

            # Legacy layers are stored uncompressed.
            target = layer_dir / "layer.tar"
            if is_gzip(blob):
                decompress(blob, target)
            else:
                shutil.copy2(blob, target)

            # The uncompressed layer's digest must equal the config's diff_id,
            # or the runtime will reject the image as corrupt.
            actual = "sha256:" + sha256_file(target)
            if actual != diff_id:
                die(
                    f"layer {idx} digest mismatch after decompression:\n"
                    f"  config diff_id: {diff_id}\n"
                    f"  actual:         {actual}"
                )

            (layer_dir / "VERSION").write_text("1.0")
            meta = {"id": layer_id, "created": created, "os": config.get("os", "linux")}
            if parent:
                meta["parent"] = parent
            # The topmost layer carries the image's runtime config.
            if idx == len(layers_rel) - 1:
                meta["config"] = config.get("config", {})
                meta["architecture"] = config.get("architecture", "")
            (layer_dir / "json").write_text(json.dumps(meta))

            legacy_layers.append(f"{layer_id}/layer.tar")
            parent = layer_id

        (out / "manifest.json").write_text(
            json.dumps([{"Config": config_name, "RepoTags": tags, "Layers": legacy_layers}])
        )

        # `repositories` is what older importers read to resolve a name:tag.
        if tags and parent:
            repos: dict[str, dict[str, str]] = {}
            for t in tags:
                name, _, tag = t.rpartition(":")
                if name:
                    repos.setdefault(name, {})[tag] = parent
            (out / "repositories").write_text(json.dumps(repos))

        with tarfile.open(dst, "w") as tf:
            for item in sorted(os.listdir(out)):
                tf.add(out / item, arcname=item)

        size = dst.stat().st_size
        print(f"wrote {dst} ({size:,} bytes, {len(legacy_layers)} layer(s), legacy layout)")


def is_gzip(path: Path) -> bool:
    with path.open("rb") as fh:
        return fh.read(2) == b"\x1f\x8b"


def decompress(src: Path, dst: Path) -> None:
    import gzip

    with gzip.open(src, "rb") as fin, dst.open("wb") as fout:
        shutil.copyfileobj(fin, fout, length=1 << 20)


def main() -> None:
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(2)
    src, dst = Path(sys.argv[1]), Path(sys.argv[2])
    tag = sys.argv[3] if len(sys.argv) > 3 else None
    if not src.exists():
        die(f"{src} does not exist")
    convert(src, dst, tag)


if __name__ == "__main__":
    main()
