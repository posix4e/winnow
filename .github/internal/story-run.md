# Story run — moved

The story runner and this runbook live in their own repository now
(posix4e/winnow#132): **https://github.com/posix4e/winnow-story** — see
`docs/story-run.md` there. The procedure is unchanged; the CLI is invoked the
same way (`scripts/winnow-story …`) from that repo's checkout, and it drives a
build of this app exactly as before, consuming this package's library products
as an ordinary client.
