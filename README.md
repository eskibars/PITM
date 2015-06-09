# PITM
### Introduction
"People in the Middle" (PITM) is an script/application that runs under [mitmproxy].  It was created as an alternative to the *--singleuser* and *--htpasswd* authentication options.  The reason for this is that, while "well behaved browsers" may follow work with proxy authentication, I found that many applications (e.g. those on Android) do not.  Instead of prompting for username/password, they merely suggest that the Internet is not working.  This defeats the purpose of having a transparent proxy.  An alternative to this is to leave mitmproxy unauthenticated, but that's not so wise in a public IP space.

### Security
##### IP-based authorization
It is worth noting that PITM trades off a little bit of security for this flexibility.  That is:
1.  Authentication is done via username/password
2.  Authorization to the user system is done via username/password
3.  Authorization to access Internet/intranet resources is done on an IP basis based upon the IPs of authenticated users

Thus, once a user logs in, the IP of that user is authorized to use mitmproxy and as a result, any system with the same IP as an authenticated user could access the Internet/intranet through mitmproxy.  Note that they *could not* access the user system, however, as that's always controlled via username/password.

##### User database
Users are stored in a sqlite3 database (*users.db*).  Passwords are salted and hashed before being stored.

### Usage
Start PITM as a mitmproxy/mitmdump script, specifying the *admin* user's password.  
```sh
$ mitmproxy -s "pitm.py <YOUR_ADMIN_PASSWORD>"
```

Make sure PITM has write access to the current directory, as it will store user details in a sqlite3 database.  Once you've specified PITM's admin password once, you can start up PITM without specifying a password.
```sh
$ mitmproxy -s "pitm.py"
```

Once mitmproxy+PITM is started, connect your browser/OS to the mitmproxy IP/port with no username/password and then navigate to any website in a browser.  You will be automatically redirected to a virtual/internal Flask application with a URL that will suggest itself as https://users.proxy.eskibars.com.  After you log in, Internet access will be granted to your IP.  If you need to add/edit users in the future, navigate a browser to https://users.proxy.eskibars.com
### Todo
1. Write tests
2. Code commenting
3. More configurability (database path, URL)
4. Logging

License
----
MIT

[mitmproxy]:https://mitmproxy.org