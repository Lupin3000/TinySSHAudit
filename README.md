# TinySSHAudit

Tiny SSH server configuration audit script

## Usage

After uploading to target host, follow these instructions as a root user:

```bash
# show help
$ ./ssh_audit.sh -h

# run with full outpu
$ ./ssh_audit.sh

# run without header
$ ./ssh_audit.sh -N
```

### Example output

```bash
[root@example ~]$ /tmp/ssh_audit.sh
 ------------------------------------------------------------------------------------------
 Execute date                     2017-03-05
 Execute time                     14:57:02
 OS                               Linux "CentOS Linux 7 (Core)"
 SSH Version                      OpenSSH_6.6.1p1, OpenSSL 1.0.1e-fips 11 Feb 2013
 ------------------------------------------------------------------------------------------
 protocol 2                       passed
 permitrootlogin no               passed
 permitemptypasswords no          passed
 permituserenvironment no         passed
 passwordauthentication no        passed
 pubkeyauthentication yes         passed
 maxauthtries 6                   failed    Protect against brute-force attacks on the password
 ignorerhosts yes                 passed
 x11forwarding yes                failed    X11 protocol was never built with security in mind
 usedns yes                       warning   Use only when your internal DNS is properly configured
 loglevel INFO                    passed
```
