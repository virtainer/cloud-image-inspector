# Security policy

The inspector reads disk images that come from URLs and uploads, so every parser
treats its input as hostile (see [Untrusted input](README.md#untrusted-input)).
A crash, hang, unbounded allocation, or a read outside the image on malformed
input is a security bug.

## Reporting a vulnerability

Please do not open a public issue. Report it privately through GitHub:
**Security → Report a vulnerability** on this repository.

Include the image (or the smallest one that reproduces the problem), the command
you ran, and what happened.

We will acknowledge the report within 7 days and keep you updated while we work
on a fix. We follow coordinated disclosure: the fix and a security advisory are
published before details are made public, and we credit the reporter in the
advisory unless you prefer otherwise.

## Supported versions

Fixes go into the latest release only.
