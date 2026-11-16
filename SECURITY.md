# Security policy

## What it covers

This covers the protocol spec ([poc-sdks/spec](poc-sdks/spec/README.md)), the three
SDKs (TypeScript, Java and Go), and the demos as the proof of concept they are.

These are reports we want:

- a request a verifier accepts that the spec says it must refuse;
- two SDKs answering one input differently;
- a way past [the owner-aware rule](README.md#the-owner-aware-rule) within what the
  request carries;
- a key, salt or proof bundle reaching a log. The README says they never do
  ([Design rules](README.md#design-rules)).

Anything already in [docs/limits.md](docs/limits.md) is known. A report that the page
understates a limit is welcome.

## How to report

Report privately, through GitHub's private vulnerability reporting:
<https://github.com/dumbsly/paztport/security/advisories/new>. Please do not open a
public issue for a vulnerability.

What helps:

- the commit and the SDK;
- the input, ideally in the shape of a case in
  [poc-sdks/spec/vectors/](poc-sdks/spec/vectors/);
- what happened, and what the spec says should have happened.

## What to expect

There is one maintainer. Replies are best effort, with no fixed response time, and
there is no bounty. If you want credit, the advisory will name you.

## Supported versions

Only `main`. This is a proof of concept with no supported release.
