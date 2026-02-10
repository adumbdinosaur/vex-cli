toy@FAILURE$ sudo ./bin/vex-cli throttle choke
[sudo] password for toy: 
[VEX-CLI] 2026/02/10 11:55:47 Logging subsystem initialized.
[VEX-CLI] 2026/02/10 11:55:47 Security: Loading management key...
[VEX-CLI] 2026/02/10 11:55:47 Security: Management key loaded successfully
[VEX-CLI] 2026/02/10 11:55:47 CMD: throttle | ARGS: choke | COMPLIANCE: score=0,status=pending,locked=true | TIME: 2026-02-10T11:55:47Z
Network profile set to: choke
toy@FAILURE$ sudo ./bin/vex-cli throttle standard
[VEX-CLI] 2026/02/10 11:55:58 Logging subsystem initialized.
[VEX-CLI] 2026/02/10 11:55:58 Security: Loading management key...
[VEX-CLI] 2026/02/10 11:55:58 Security: Management key loaded successfully
[VEX-CLI] 2026/02/10 11:55:58 CMD: throttle | ARGS: standard | COMPLIANCE: score=0,status=pending,locked=true | TIME: 2026-02-10T11:55:58Z
Network profile set to: standard
toy@FAILURE$ ^C
toy@FAILURE$ 


toy@FAILURE$ sudo ./bin/vexd --dry-run
[sudo] password for toy: 
[VEX-CLI] 2026/02/10 11:55:31 Logging subsystem initialized.
[VEX-CLI] 2026/02/10 11:55:31 Starting vexd (Protocol 106-V) [DRY-RUN MODE] …
[VEX-CLI] 2026/02/10 11:55:31 Security: Loading management key...
[VEX-CLI] 2026/02/10 11:55:31 Security: Management key loaded successfully
[VEX-CLI] 2026/02/10 11:55:31 State: No persisted state found, using defaults
[VEX-CLI] 2026/02/10 11:55:31 Compliance state: LOCKED — penalties will be enforced
[VEX-CLI] 2026/02/10 11:55:31 [DRY-RUN] Skipping all subsystem initialization (no kernel changes)
[VEX-CLI] 2026/02/10 11:55:31 State: Persisted (profile=standard, cpu=100%, locked=true, by=default)
[VEX-CLI] 2026/02/10 11:55:31 All subsystems initialized. Daemon ready. [DRY-RUN — no enforcement]
[VEX-CLI] 2026/02/10 11:55:31 [DAEMON] STARTED: penalty_active=true, dry_run=true
[VEX-CLI] 2026/02/10 11:55:31 IPC: Listening on /run/vex-cli/vexd.sock
[VEX-CLI] 2026/02/10 11:55:47 [IPC] REQUEST: cmd=throttle args=map[profile:choke]
[VEX-CLI] 2026/02/10 11:55:47 [DRY-RUN] Would apply network profile: choke
[VEX-CLI] 2026/02/10 11:55:47 [THROTTLER] PROFILE_CHANGED: profile=choke (requested=choke), source=cli
[VEX-CLI] 2026/02/10 11:55:47 State: Persisted (profile=choke, cpu=100%, locked=true, by=cli)
[VEX-CLI] 2026/02/10 11:55:58 [IPC] REQUEST: cmd=throttle args=map[profile:standard]
[VEX-CLI] 2026/02/10 11:55:58 [DRY-RUN] Would apply network profile: standard
[VEX-CLI] 2026/02/10 11:55:58 [THROTTLER] PROFILE_CHANGED: profile=standard (requested=standard), source=cli
[VEX-CLI] 2026/02/10 11:55:58 State: Persisted (profile=standard, cpu=100%, locked=true, by=cli)