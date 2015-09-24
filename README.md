# ASP.NET Self-created token authentication example
Simple example of how to protect an ASP.NET vNext / MVC6 (working against beta 7 as of 24/09/2015) project using simple self-created JWT bearer tokens for local username/password checking.

**DO NOT USE IN PRODUCTION**

The following things, at very least, should be addressed:

1. The hard coded private keys in Startup.cs should be changed and factored out to some sort of secure storage.
2. The error handling is very simple.
3. The username and password checking using an "if" statement should be replaced with checking against some sort of repository, and identities created etc.

The strategy shown here is based largely on [this StackOverflow answer](http://stackoverflow.com/a/29698502/789529) by @mdekrey, but updated for the latest beta and slightly tweaked to be a more complete example.
