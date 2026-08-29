# Security policy

This is a research prototype. Do not deploy it as a security boundary for production systems.

## Supported scope

Security reports should concern the source in the tagged research preview and include a minimal reproduction that does not target third-party systems. Public disclosure should avoid live credentials, personal data, or operational authorization material.

## Reporting

Until a dedicated private reporting channel is published, prepare a minimal encrypted or private report and contact the project owner through the future repository's private security-advisory feature. Do not create a public issue containing a secret or exploit.

## Safe testing

- use disposable user-space processes and temporary directories;
- do not modify firmware, host kernels, drivers, boot settings, or personal files;
- do not scan or attack systems without their owner's explicit authorization;
- treat any surprising side effect as a stop condition.

The project makes no universal security or certification claim.
