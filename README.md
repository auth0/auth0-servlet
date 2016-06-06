# Auth0 and Java

[Auth0](https://www.auth0.com) is a cloud service that provides a turn-key solution for authentication, authorization and Single Sign On. 

You can use  [Auth0](https://www.auth0.com) to add username/password authentication, support for enterprise identity like Active Directory or SAML and also for social identities like Google, Facebook or Salesforce among others to your web, API and mobile native apps. 

## Learn how to use it

[Please read this tutorial](https://docs.auth0.com/server-platforms/java) to learn how to use this SDK.

## Extensibility points
### Auth0 Servlet Callback

#### protected void onSuccess(HttpServletRequest req, HttpServletResponse resp)

Here you can configure what to do after successful authentication. By default, it redirects to the URL configured in the `web.xml`

####	protected void onFailure(HttpServletRequest req, HttpServletResponse resp, Exception ex) 

Here you can configure what to do after failure authentication. By default, it redirects to the URL configured in the `web.xml`
			
#### protected void store(Tokens tokens, Auth0User user, HttpServletRequest req)

Here you can configure where to store the Tokens and the User. By default, they're stored in the `Session` in the `tokens` and `user` fields

### Auth0 Filter

#### protected Tokens loadTokens(ServletRequest req, ServletResponse resp)

You can specify where to get the tokens from. If you changed where they're saved in the Callback, then you should change it here. Now, they're saved in the `tokens` field of the `Session`

#### protected Auth0User loadUser(ServletRequest req)

You can specify where to get the User from. If you changed where they're saved in the Callback, then you should change it here. Now, they're saved in the `user` field of the `Session`

#### protected void onSuccess(ServletRequest req, ServletResponse resp, FilterChain next, Auth0User user)

By default, on success we wrap the `Request` with the `Auth0Request` so that we change the `UserPrincipal` to be a `Auth0User`. You can of course change that here.

#### protected void onReject(ServletRequest req, ServletResponse resp, FilterChain next, Auth0User user)

By default, on we redirect to the URL configured in the `web.xml`. You can override this and change that.

## Issue Reporting

If you have found a bug or if you have a feature request, please report them at this repository issues section. Please do not report security vulnerabilities on the public GitHub issue tracker. The [Responsible Disclosure Program](https://auth0.com/whitehat) details the procedure for disclosing security issues.

## What is Auth0?

Auth0 helps you to:

* Add authentication with [multiple authentication sources](https://docs.auth0.com/identityproviders), either social like **Google, Facebook, Microsoft Account, LinkedIn, GitHub, Twitter, Box, Salesforce, amont others**, or enterprise identity systems like **Windows Azure AD, Google Apps, Active Directory, ADFS or any SAML Identity Provider**.
* Add authentication through more traditional **[username/password databases](https://docs.auth0.com/mysql-connection-tutorial)**.
* Add support for **[linking different user accounts](https://docs.auth0.com/link-accounts)** with the same user.
* Support for generating signed [Json Web Tokens](https://docs.auth0.com/jwt) to call your APIs and **flow the user identity** securely.
* Analytics of how, when and where users are logging in.
* Pull data from other sources and add it to the user profile, through [JavaScript rules](https://docs.auth0.com/rules).

## Create a free account in Auth0

1. Go to [Auth0](https://auth0.com) and click Sign Up.
2. Use Google, GitHub or Microsoft Account to login.

## Issue Reporting

If you have found a bug or if you have a feature request, please report them at this repository issues section. Please do not report security vulnerabilities on the public GitHub issue tracker. The [Responsible Disclosure Program](https://auth0.com/whitehat) details the procedure for disclosing security issues.

## Author

[Auth0](auth0.com)

## License

This project is licensed under the MIT license. See the [LICENSE](LICENSE.txt) file for more info.
