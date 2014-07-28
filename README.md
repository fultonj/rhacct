rhacct
======

Allows an org admin to create a user account within the Red Hat Customer Portal (access.redhat.com). rhacct is shortfor Red Hat Account Tool and is prounced "racket", as "turn down that racket"

```
Usage: rhacct [options] user@example.com

rhacct: add users to or modify users in the Red Hat Customer Portal. Uses
email address to idenitfy user. Created username is email address and password
is default value. Assumes organizational admin credentials are in
/etc/rhacct.conf. Otherwise prompts for credentials.

Options:
  -h, --help            show this help message and exit
  -e, --explain         Explains permissions; e.g. 'rhacct -e'
  -l, --list            Prints all users; e.g. 'rhacct -l'
  -r, --report          Prints details of USER; e.g. 'rhacct -r
                        user@example.com'
  -d, --disable         Disables user USER (users cannot be deleted); e.g.
                        'rhacct -d user@example.com'
  -m, --modify          Modify an existing user USER; e.g. 'rhacct -m
                        user@example.com -p knowledge'
  -f FIRST, --first-name=FIRST
                        Sets first name; e.g. 'rhacct -f Jane -m
                        user@example.com'
  -s LAST, --surname=LAST
                        Sets surname name; e.g. 'rhacct -s Doe -m
                        user@example.com'
  -c, --create          Create user USER; e.g. 'rhacct -p knowledge -f Jane -s
                        Doe -c user@example.com'
  -p PERMISSIONS, --perm=PERMISSIONS
                        (Re)Assigns permissions to USER; PERMISSIONS must be
                        comma separated list of permissions (no spaces) see -e
                        for permission names; all passed permissions are
                        enabled; if permission not specified that permission
                        is disabled; e.g. 'rhacct -p cases,knowledge -c
                        user@example.com'
  -k, --keep            Only used with -m and -p to not remove existing
                        permissions; this option is good for adding an extra
                        priviliege; e.g. 'rhacct -m user@example.com -k -p
                        downloads'
  -g, --generate-config
                        Generate config file (rhacct.conf) in current working
                        directory which can be stored in /etc/rhacct.conf. If
                        said file is present rhacct will not prompt for input
                        each time it is run.
  -v, --verbose         Print status messages to stdout
```
