# ASP.NET Self-created token authentication example
A simple example of how to protect an ASP.NET 5 / MVC 6 (working against beta 8 as of 19/10/2015) project using simple self-created JWT bearer tokens for local username/password checking.

**DO NOT USE IN PRODUCTION**

This example is to show the principles required to acheive local token authentication, and **the following things should be changed before production usage**:

1. The random-generated private keys in Startup.cs should be changed and factored out to some sort of secure storage and shared amongst all app servers serving your site.
2. The error handling is very simple - and may leak application info to the end users as it returns the exception message.
3. The username and password checking using an "if" statement should be replaced with checking against some sort of repository, and identities generated from that.

The strategy shown here is based on [this StackOverflow answer](http://stackoverflow.com/a/29698502/789529) by @mdekrey, updated for the latest beta and rationalised to be a slightly simpler, complete example.

You can find more information about the principles in [my StackOverflow answer](http://stackoverflow.com/a/33217122/789529) to the same question.
