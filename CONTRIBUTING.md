# Contributing

Thanks for taking a look. This project talks to a proprietary protocol, so a few rules
are stricter than usual.

## Getting started

```bash
git clone https://github.com/Yarfer800/aiowapy
cd aiowapy
uv sync --group dev
uv run pytest
```

Python 3.11+ is required. `uv` handles the virtualenv and the lockfile.

## Checks before a pull request

```bash
uv run ruff check .
uv run ruff format --check .
uv run mypy src
uv run pytest
```

All four must pass. CI runs the same commands on 3.11, 3.12 and 3.13; a patch that only
passes locally usually means a version-specific assumption.

## Layout

```
src/aiowapy/
├── client.py        public Client: connect, send, receive, reconnect
├── events.py        events handed to application code
├── router.py        filters and handler dispatch
├── models.py        data types shared by every layer (MediaInfo, Peer, StoredMessage)
├── session.py       pairing and login state machine
├── creds.py         device credentials
├── pb.py            minimal protobuf helpers
├── protocol/        wire formats: wabinary, noise, stream, transport, messages, ...
├── crypto/          primitives, Signal sessions, sender keys, media, XEdDSA
├── messaging/       pipeline: devices, sessions, messenger, groups, media, appstate
└── store/           SQLite session file and migrations
```

Layer rules are enforced by `tests/test_import_graph.py`: `protocol` and `crypto` never
import the client, `store` never imports the network, and `events`/`models` stay
data-only. If a change needs a new edge in that graph, update the test deliberately
instead of working around it.

## Style

- Line length 100, ruff with `E F I UP B SIM TID`.
- Type hints everywhere; `mypy --strict` is the gate.
- No module-level docstring at the top of a file. Put the explanation on the class or
  function that carries the behaviour, or in `docs/`.
- Comments explain *why*, not what. Protocol quirks deserve a comment; obvious code does
  not.
- Public API is exported from `aiowapy/__init__.py`; everything else is internal.

## Adding or changing protocol behaviour

1. **Find the reference.** Both [whatsmeow](https://github.com/tulir/whatsmeow) (MPL-2.0)
   and [Baileys](https://github.com/WhiskeySockets/Baileys) (MIT) are useful. Read how
   they build the stanza, which fields they set, and in what order.
2. **Write the test first**, with the exact bytes from the reference. Fixtures for
   protobuf payloads live in `tests/fixtures/protocol/`.
3. **Implement it yourself.** Do not translate files from whatsmeow: MPL-2.0 is
   file-level copyleft, and a translated file would make this project a mixture of
   licences. Behaviours and wire formats are not copyrightable; code is.
4. **Document the quirk** in the docstring and, if it is user-visible, in `docs/`.
5. **Add an offline round-trip test.** The strongest tests build one side of a Signal or
   sender-key session with test code and decrypt with the library (or the other way
   around). If a change cannot be tested without a live account, say so in the pull
   request.

Never commit captured traffic, session files, phone numbers or logs from a real account.
`*.session`, `*.har`, `*.pcap`, `notes/` and `tools/capture/` are ignored for a reason.

## Commits

Conventional Commits, one logical change per commit:

```
feat(groups): rotate the sender key when a member leaves
fix(client): stop reconnecting after a logged-out error
docs: document history sync
```

The subject is imperative, lowercase after the type, under ~72 characters. The body
explains the problem and the decision, not the diff.

## Review

The maintainer reviews with a side-by-side diff in neovim:

```bash
scripts/review.sh            # working tree against HEAD
scripts/review.sh HEAD~3     # any range git diff understands
```

Comments are attached to file and hunk anchors. If you are reviewing someone else's
change, the same script works — it prints the notes when the window closes.

## Documentation

`docs/` is a mkdocs site with mkdocstrings:

```bash
uv sync --group docs
uv run mkdocs serve          # http://127.0.0.1:8000
uv run mkdocs build --strict
```

API pages pull docstrings straight from the source, so improving a docstring improves
the site. The README demo GIF is generated from a real run:

```bash
uv run --with pillow python scripts/make_demo_gif.py
```

## Releasing

1. Bump `version` in `pyproject.toml` and `src/aiowapy/__init__.py`.
2. Add a `CHANGELOG.md` entry.
3. Create a GitHub release with tag `vX.Y.Z`.
4. `.github/workflows/workflow.yml` builds the wheel, checks it with `twine` and
   publishes to PyPI through trusted publishing.

No tokens live in the repository.

## Licence

MIT. By contributing you agree that your changes are released under the same licence.
