# php-kadm5

## What is it?

This is a PHP extension that exposes libkadmin functionality in PHP. It's extremely useful if you are looking to write a web UI for user account management in your organization.

## What do I need?

* An up to date version of MIT Kerberos V. 1.9 or newer *should* build, but that was before the policy related functions were added. These days, 1.12 and later are what I usually build against.
* **Heimdal and other alternative Kerberos implementations are not supported, since they do not use MIT's kadmin protocol.**
* PHP 7. If you need PHP 5 support, please build the `php5` branch. Please note that this branch will **not** be receiving any future feature or security patches.

## How do I build it?

Debian users: just run `dpkg-buildpackage`.

Everyone else: `cd kadm5 && phpize && ./configure && make && make install`

## Authors

* Dan Fuhry <dan@fuhry.com>
** Current maintainer: Kerberos 1.9 support, bugfixes, PHP7 support, kadm5_get_policy support
* Holger Burbach <holger.burbach@gonicus.de>
** Original author
