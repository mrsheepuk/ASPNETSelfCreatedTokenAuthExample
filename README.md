# ASPNETSelfCreatedTokenAuthExample
Simple example of how to protect an ASP.NET vNext / MVC6 (beta 7) project using simple self-created JWT bearer tokens.

**DO NOT USE IN PRODUCTION**

The following things, at very least, should be addressed:

1. The hard coded private keys in Startup.cs should be changed and factored out to some sort of secure storage.
2. The error handling is very simple.
3. The username and password checking using an "if" statement should be replaced with checking against some sort of repository, and identities created etc.

