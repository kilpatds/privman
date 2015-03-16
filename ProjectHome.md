# Privman #
Privman is a library that makes it easy for programs to use privilege separation, a technique that prevents the leak or misuse of privilege from applications that must run with some elevated permissions.  The Privman library simplifies the otherwise complex task of separating the application, protecting the system from compromise if an error in the application logic is found

Applications that use the Privman library split into two halves, the half that performs valid privileged operations, and the half that contains the application's logic.  . The library uses configuration files to provide fine-grained access control for the privileged operations, limiting exposure in even of an attack against the application. When the application is compromised, the attacker gains only the privileges of an unprivileged user and the specific privileges granted to the application by the application's Privman configuration file.

## Quick Start Guide ##

### Installation ###
```
$ ./configure
$ make
$ sudo make install
```

### Your application ###

```
#include <privman.h>

int main()
{
    /* Register any custom handlers here */

    priv_init();

    /* The rest of your app goes here */
    int fd = priv_open("/etc/shadow", O_RDONLY);
    /* Etc.  Use priv_* to perform operations that require privilege */

    return 0;
}
```

### Your Application's config ###bind {
   echo
   http
   8080
}

open_ro {
    /etc/shadow
    /tmp/*
}

unpriv_user nobody
chroot /tmp/chroot```