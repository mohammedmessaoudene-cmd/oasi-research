# Security policy

This is a research prototype. Do not deploy it as a security boundary for production systems.

## Supported scope

Security reports should concern the source in the tagged research preview and include a minimal reproduction that does not target third-party systems. Public disclosure should avoid live credentials, personal data, or operational authorization material.

## Reporting

Send an initial, minimal, non-sensitive report to
`mohammed.messaoudene@univ-temouchent.edu.dz`. Do not include credentials,
personal data, operational authorization material, or exploit details in that
first message. If a private exchange is needed, agree on a channel explicitly.
This policy promises neither encryption, a response time, an embargo, a bounty,
nor acceptance of a report. Do not create a public issue containing a secret or
exploit.

## Safe testing

- use disposable user-space processes and temporary directories;
- do not modify firmware, host kernels, drivers, boot settings, or personal files;
- do not scan or attack systems without their owner's explicit authorization;
- treat any surprising side effect as a stop condition.

The project makes no universal security or certification claim.
