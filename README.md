# Auth0 and Java

[Auth0](https://www.auth0.com) is a cloud service that provides a turn-key solution for authentication, authorization and Single Sign On. 

You can use  [Auth0](https://www.auth0.com) to add username/password authentication, support for enterprise identity like Active Directory or SAML and also for social identities like Google, Facebook or Salesforce among others to your web, API and mobile native apps. 

## Learn how to use it

[Please read this tutorial](https://docs.auth0.com/server-platforms/java-servlet) to learn how to use this SDK.

You may also find our Sample projects the easiest way to learn simply by installing and running, then inspecting the samples code.

## Extensibility points

### Auth0Config

Please take a look at the sample that accompanies this library for an easy seed project to see this working.

Essentially, `src/main/webapp/WEB-INF/web.xml` is where all the configuration is added.

Here is a breakdown of attributes and what they do:

`auth0.domain` - This is your auth0 domain (tenant you have created when registering with auth0 - account name)

`auth0.clientId` - This is the client id of your auth0 application (see Settings page on auth0 dashboard)

`auth0.clientSecret` - This is the client secret of your auth0 application (see Settings page on auth0 dashboard)

`auth0.onLogoutRedirectTo` - This is the page / view that users of your site are redirected to on logout. Should start with `/`


## Extension Points in Library

Most of the library can be extended, overridden or altered according to need. It is designed to provide a base
library framework but it easy to replace, extend or modify any of the existing classes to customise according to need.

### Auth0CallbackHandler

Designed to be very flexible, the existing implementation may be enough in most cases. However, it is easy to inherit
 the default implementation and override any super class methods accordingly. The CallbackHandler - expects to receive
 an authorization code - using OIDC / Oauth2 Authorization Code Grant Flow.

List of functions available for override:

#### protected void onSuccess(HttpServletRequest req, HttpServletResponse resp)

Here you can configure what to do after successful authentication.

####  protected void onFailure(HttpServletRequest req, HttpServletResponse resp, Exception ex)

Here you can configure what to do after failure authentication.

####  protected void store(final Credentials tokens, final Auth0User user, final HttpServletRequest req)

Here you can configure where to store the Tokens and the User. By default, they're stored in the `Session` in the `tokens` and `auth0User` fields

#### protected boolean isValidState(final HttpServletRequest req)

By default, this library expects a Nonce value in the state query param as follows `state=nonce=B4AD596E418F7CE02A703B42F60BAD8F` where `xyz`
is a randomly generated UUID.

The NonceFactory can be used to generate such a nonce value. State may be needed to hold other attribute values hence why it has its
own keyed value of `nonce=B4AD596E418F7CE02A703B42F60BAD8F`. For instance in SSO you may need an `externalCallbackUrl` which also needs
to be stored down in the state param - `state=nonce=B4AD596E418F7CE02A703B42F60BAD8F&externalCallbackUrl=http://localhost:3099/callback`


### Auth0 Filter

Customise according to need. Default behaviour is to test for presence of `Auth0User` and `Tokens` acquired after authentication
callback. And to parse and verify the validity (including expiration) of the associated JWT id_token.


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
