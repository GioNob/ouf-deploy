# Retained cohort source snapshots

These files are immutable source bytes used only to verify historical capsule
membership. They are not executable installation defaults or renewed authority.

- authorization-8987585e7cf4.py.txt preserves the previously qualified snapshot.
- human-session-11dc195dfa0f.py.txt is the exact human_session.py from commit
  45b78c009aca4f9a93b1ffbfafffd74a3b4555e5. Its SHA256 is
  11dc195dfa0fa63a35e9ba3bf0b6a65fd73e3d76be7efa9fed8b4d2f852e8d75,
  matching releases/chatbot-file-preparation-capsule-20261015.json.

The launcher test checks the exact retained bytes and rejects the current shared
module under the old manifest. Neither the manifest, package pins, live login
implementation nor consumed deployment claims are changed by this fixture.
