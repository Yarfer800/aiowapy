# Agent notes

## Code review

When the user asks to review the changes, do not paste diffs into the chat.
Run the review window from the repository root and wait for it to exit:

```bash
scripts/review.sh            # working tree against HEAD
scripts/review.sh HEAD~3     # or any range git diff understands
```

The command opens neovim with the diff (old | new) and a notes buffer, blocks
until the window closes, and prints the notes the user wrote, or
`no review comments`. Comments are grouped by file and hunk anchor.

Treat the printed notes as review feedback: fix the code, then re-run the
review if the user asks for another round. Never invent notes the user did not
write, and do not edit `REVIEW.md` yourself.

The window needs kitty or a tmux session; the workspace lives in
`/tmp/opencode/review/`.
