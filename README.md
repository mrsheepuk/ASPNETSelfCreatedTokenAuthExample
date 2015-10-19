# ASP.NET Self-created token authentication example
Simple example of how to protect an ASP.NET vNext / MVC6 (working against beta 8 as of 19/10/2015) project using simple self-created JWT bearer tokens for local username/password checking.

**DO NOT USE IN PRODUCTION**

The following things, at very least, should be addressed:

1. The random-generated private keys in Startup.cs should be changed and factored out to some sort of secure storage.
2. The error handling is very simple.
3. The username and password checking using an "if" statement should be replaced with checking against some sort of repository, and identities created etc.

The strategy shown here is based largely on [this StackOverflow answer](http://stackoverflow.com/a/29698502/789529) by @mdekrey, updated for the latest beta and rationalised to be a slightly simpler, complete example.
