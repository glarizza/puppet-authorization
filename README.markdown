## Mac Authorization Puppet Types/Providers

Up until version 10.9 of OS X (i.e. Mavericks), the authorization database has
lived in `/etc/authorization`, and core Puppet has had a `macauthorization`
type to manage this file.

As of version 10.9, the authorization database is actually a SQLite database
that lives at /var/db/auth.db.  This database contains both rules and rights
in one table - `rules`.  You can view all the rules and the rights like so:

```
└(~)▷ sudo sqlite3 /var/db/auth.db
SQLite version 3.7.13 2012-07-17 17:46:21
Enter ".help" for instructions
Enter SQL statements terminated with a ";"
sqlite>

sqlite> select * from rules;
1|is-lpadmin|2|1|_lpadmin||2147483647|0|10000|0|408854363.334574|408854363.334574||||
2|authenticate-session-user|2|1|||2147483647|12|10000|0|408854363.334574|408854363.334574||||Same as authenticate-session-owner.
3|authenticate|2|3||||1|10000|0|408854363.334574|408854363.334574||||
4|admin|2|1|admin||2147483647|9|10000|0|408854363.334574|408854363.334574||||
5|is-admin|2|1|admin||2147483647|1|10000|0|408854363.334574|408854363.334574||||Verify that the user asking for authorization is an administrator.
6|entitled|2|3||||1|1|0|408854363.334574|408854363.334574||||
7|appserver-user|2|1|appserverusr||2147483647|8|10000|0|408854363.334574|408854363.334574||||
8|authenticate-session-owner-or-admin|2|1|admin||2147483647|12|10000|0|408854363.334574|408854363.334574||||Authenticate either as the owner or as an administ
rator.

###  And so on... ###
```

Because of this change, Puppet's provider for macauthorization needed to change.
Also, since this provider needed to change, I felt it was a good time to rip the
type and provider out of core and make some changes. Initially, both rights and
rules were modeled inside one resource type. This was probably not the best
decision in the world. Yes, currently the implementation for both rights and
rules in the authorization database is IDENTICAL (i.e. you're making the same
calls to the `security` binary to change either rights or rules), but just because
that's the case doesn't mean that the model should be collapsed. I'm intentionally
splitting rights and rules into separate resources (they can easily be folded
together in the future if need be).

## Caution: ALPHA CODE!

This is incredibly 'alpha' code. I'm doing a SQLite DB call to get the list of
rules and rights, and then using the `security` binary to make any changes.
While the calls to `security` are sound, the SQLite DB query is probably a bit
hackish. There are most likely better ways to handle this, and I'm open to
suggestions.
