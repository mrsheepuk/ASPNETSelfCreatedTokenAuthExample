# ASP.NET Self-created token authentication example
A simple example of how to protect an ASP.NET 5 / MVC 6 project using simple self-created JWT bearer tokens for local username/password checking. Working against RC1 as of 19/11/2015 - see the beta8 and beta7 branches if you're using older framework versions.

**DO NOT USE AS-IS IN PRODUCTION**

This example is to show the principles required to acheive local token authentication, and **the following things should be changed before production usage**:

1. The random-generated private keys in Startup.cs should be changed and factored out to some sort of secure storage and shared amongst all app servers serving your site. Using the data protection API to ensure the keys are rotated and secured would be perfect, but I've not worked out how to do that yet (please submit a pull request if you get that working!).
2. The error handling is very simple - and may leak application info to the end users as it returns the exception message.
3. The username and password checking using an "if" statement should be replaced with checking against some sort of repository, and identities generated from that.
4. Consider whether the token refresh strategy (the TokenController Get action) is appropriate for your application - [this StackOverflow question and answer may help you decide what is best for your application](http://stackoverflow.com/questions/26739167/jwt-json-web-token-automatic-prolongation-of-expiration)

You can find more information about the principles in [my StackOverflow answer here](http://stackoverflow.com/a/33217122/789529). This strategy is based on [this StackOverflow answer](http://stackoverflow.com/a/29698502/789529) to the same question by @mdekrey, updated for the RC1 and rationalised to be a slightly simpler, complete example.
