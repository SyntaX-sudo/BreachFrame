# Security policy

## Scope and design

BreachFrame is an **offline, defensive** analysis tool. It is designed so that:

- it only analyses files you explicitly import (or the built-in labs);
- it never executes commands, installs packages or connects to hosts found in
  those files;
- it performs no scanning or exploitation of any network target;
- simulations run on the in-memory model only and are labelled as such;
- detected credentials are redacted before storage, display or export.

A bug that breaks any of these guarantees is a security issue. Examples: a crafted
input that causes code execution, an unredacted secret, script execution in an
exported report, or a path that reads files the user did not select.

## Supported versions

Only the latest published release receives security fixes.

## Reporting a vulnerability

Please **do not open a public issue**. Use GitHub's
[private vulnerability reporting](https://github.com/SyntaX-sudo/BreachFrame/security/advisories/new)
for this repository. Include:

- affected version and OS;
- a minimal input file or steps to reproduce;
- the impact you observed.

You should receive an acknowledgement within 7 days. Fixes are released as soon
as practical, and reporters are credited unless they ask otherwise.

## Responsible use

BreachFrame is for auditing systems you own or are authorised to assess, and for
education with the bundled labs. You are responsible for complying with the laws
and agreements that apply to you.
