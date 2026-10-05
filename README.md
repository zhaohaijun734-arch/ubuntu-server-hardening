# ubuntu-server-hardening

SSH + firewall + fail2ban hardening for Ubuntu servers with a safety net:

- 10-minute automatic rollback if you lock yourself out
- pre-change backups with verified restore points
- post-change live verification
- no `apt upgrade` in the same session (unrelated variables)

Covers: disabling password login, restricting root direct login, ufw
defaults that don't break existing services, fail2ban jails that actually
catch logs (and the "installed but zero bans" debugging path).

Ships as an agent SKILL.md: install by copying `SKILL.md` into your agent's
skills directory.

MIT License.
