# Detection Anchor Taxonomy

This directory defines the taxonomy used by the auditor to classify Falco rule fields by what they are anchored to, and to predict whether each rule will survive realistic evasion.

## The problem

A Falco rule can look logically correct and still be easy to bypass. The reason is that not all condition fields are equally trustworthy. Some reflect kernel-observed facts such as the syscall that really happened. Others reflect attacker-controlled strings such as the path a process used or the name of the binary it launched.

Concretely:

- `evt.type = setns` survives binary rename and custom-binary attempts.
- `proc.name = nsenter` fails under the same techniques.
- `fd.name contains "docker.sock"` and `fd.name startswith "/host/"` fail under symlink and fd-alias evasions.
- `container.mounts`-based rules close those gaps because the mount table is set at container creation and is not rewritten from inside the container.

The taxonomy explains those outcomes as a property of the anchor, not as isolated rule bugs.

## Core insight

Evasion resistance depends on what the rule must trust:

- If a condition is anchored to a kernel-observed syscall fact, userspace cannot spoof that fact after the event occurs.
- If a condition is anchored to runtime mount metadata, the attacker cannot rewrite that metadata from inside the container.
- If a condition is anchored to a pathname string or process name string, the attacker usually controls it directly.

For mixed rules, the weakest required anchor dominates an `AND` branch. If a strong branch can fire independently in an `OR`, that branch should be assessed on its own.

## The four anchor classes

### Syscall-anchored

Syscall-anchored conditions depend on facts the kernel observed directly, such as `evt.type = setns`, `evt.type = unshare`, or descriptor type information like `fd.type = unix`. The attacker can avoid performing that action, but cannot make a `setns` event look like something else once it happens. In this taxonomy, that makes syscall anchors high resistance.

### Mount-anchored

Mount-anchored conditions depend on container runtime metadata such as `container.mounts`. That metadata is set when the container starts and is not rewritten from inside the container, so symlink tricks and alternate access paths do not change it. Mount anchors are also high resistance, though they usually detect dangerous capability rather than a single file access.

### Path-anchored

Path-anchored conditions depend on pathname strings like `fd.name` and `fd.directory`. Falco reports the path that was used, not necessarily the resolved target, so a symlink, `/dev/fd/N`, `/proc/self/fd/N`, or a different mount destination can all change what the rule sees. That makes path anchors low resistance.

### Name-anchored

Name-anchored conditions depend on process identity strings such as `proc.name`, `proc.exepath`, `proc.cmdline`, `proc.pname`, and `proc.args`. Those strings are easy to change with renaming, wrapper binaries, custom tooling, or argument changes. Name anchors are therefore low resistance and should be treated as supplementary evidence rather than primary detection logic.

## Class summary

| Class | What the attacker controls | Known evasion techniques | Project example |
|---|---|---|---|
| `syscall-anchored` | Whether to perform the underlying action at all | Switching to a different behavior or syscall, not spoofing the observed event | `Container Calling setns Syscall` stayed 5/5 in E1 and E1b; `Container Calling unshare Syscall` was added after E2 exposed a separate syscall gap |
| `mount-anchored` | Only the container spec before launch, not the live mount metadata from inside the container | None from inside-container pathname tricks | `Container With Docker Socket Mounted` and `Container With Host Root Mounted` both achieved 5/5 after the P1/P2 hardening |
| `path-anchored` | The path string used to access an object | Symlink, fd redirection, `/proc/self/fd`, alternate mount path | `Container Docker Socket Access` and `Container Writing Under Mounted Host Root` both failed against E3 and E4 evasion-specific accesses |
| `name-anchored` | Binary name, executable path, command line, wrapper process | Binary rename, custom binary, alternative tool, cmdline obfuscation | `Container Using nsenter` was bypassed by renamed and custom binaries |

## Field classification notes

`field_classification.yaml` keeps a simple `field -> class` mapping so the planned auditor can load it directly. The slightly ambiguous fields are classified as follows:

- `evt.arg.request` is `syscall-anchored` because it is a kernel-observed syscall argument, not a free-form process label. The attacker can choose a different request, but cannot spoof the value for the event that happened.
- `fd.type` and `fd.typechar` are `syscall-anchored` because they describe the resolved descriptor or object type reported by Falco from kernel event context. A unix socket can be hidden behind a different path string, but it cannot be made to appear as a regular file by renaming it.
- `fd.nameraw` and `fd.sip.name` are treated as `path-anchored` in the generalized auditor because they are still string locators for the accessed target. The attacker can often change the visible raw path or network endpoint identifier without changing the broader behavior class.
- `proc.exepath` stays `name-anchored`, not `path-anchored`, because here the security question is process identity, not file-access resolution. Renaming or relocating the executable changes the identity string the rule sees.
- `container.id`, `container.name`, and `container.image.repository` are labeled `metadata` because they scope or enrich alerts rather than forming the attack-detection anchor.
- The bare `container` token used in several rules is intentionally outside this mapping because it is not a dotted field reference and acts as a container-scope shorthand rather than an anchor class.

## Expected behavior

- Syscall-anchored rules should survive name spoofing.
- Path-anchored rules should fail when the attacker changes the visible pathname.
- Mount-anchored rules should survive those pathname evasions because the mount table does not depend on the access path.
- Name-anchored rules should be treated as fragile even when they are still useful as supplementary context.
