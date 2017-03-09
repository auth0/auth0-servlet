
[![Build Status](https://travis-ci.org/auth0/auth0-servlet.svg?branch=v4)](https://travis-ci.org/auth0/auth0-servlet)
[![codecov](https://codecov.io/gh/auth0/auth0-servlet/branch/v4/graph/badge.svg)](https://codecov.io/gh/auth0/auth0-servlet)

# Auth0 Servlet

A simple (plain) Java library that allows you to use Auth0 with Java for server-side MVC web apps. Aims not to introduce specific frameworks or libraries such as Spring.

## Download

Get Auth0 Servlet via Maven:

```xml
<dependency>
  <groupId>com.auth0</groupId>
  <artifactId>auth0-servlet</artifactId>
  <version>4.0.0</version>
</dependency>
```

or Gradle:
```groovy
compile 'com.auth0:auth0-servlet:4.0.0'
```


## Configuration

### Auth0 Dashboard
1. On the [Auth0 Dashboard](https://manage.auth0.com/#/clients) create a new Client of type `Regular Web Application`. 
1. Add the URL that will be called on an OAuth successful login to the Allowed Callback URLs. i.e.: `https://mysite.com/callback`.
1. Add the URL that will be called on logout to the Allowed Logout URLs. i.e.: `https://mysite.com/logout`.
1. Copy the `Domain`, `Client ID` and `Client Secret` values at the top of the page and use them to configure the Java Application.


### Java Application
You need to add the library classes to the deployment descriptor file located in `src/main/webapp/WEB-INF/web.xml`.

1. Declare the `Auth0RedirectServlet` servlet in your application. Change the `com.auth0.redirect_on_success` and `com.auth0.redirect_on_error` variables to the path of the application you want to be called in each case. Usually, this would be the protected path and the login page respectively.

    ```xml
    <servlet>
        <servlet-name>RedirectCallback</servlet-name>
        <servlet-class>com.auth0.example.Auth0RedirectServlet</servlet-class>
        <init-param>
            <param-name>com.auth0.redirect_on_success</param-name>
            <param-value>/portal/home</param-value>
        </init-param>
        <init-param>
            <param-name>com.auth0.redirect_on_error</param-name>
            <param-value>/login</param-value>
        </init-param>
    </servlet>
    ```

1. Configure the mapping of the `Auth0RedirectServlet` servlet to listen for calls to the Callback URL path defined previously.

    ```xml
    <servlet-mapping>
        <servlet-name>RedirectCallback</servlet-name>
        <url-pattern>/callback</url-pattern>
    </servlet-mapping>
    ```

1. Declare the `Auth0Filter` filter in your application by adding the snippet below. Change the `com.auth0.redirect_on_authentication_error` to the path of the application you want to be called after a failed login. Usually, this would be the login page.

    ```xml
    <filter>
        <filter-name>AuthFilter</filter-name>
        <filter-class>com.auth0.example.Auth0Filter</filter-class>
        <init-param>
            <param-name>com.auth0.redirect_on_authentication_error</param-name>
            <param-value>/login</param-value>
        </init-param>
    </filter>
    ```

1. Configure the mapping of the `Auth0Filter` filter to protect the endpoints were the user should be authenticated before accessing them.

    ```xml
    <filter-mapping>
        <filter-name>AuthFilter</filter-name>
        <url-pattern>/portal/*</url-pattern>
    </filter-mapping>
    ```

1. Add the Auth0 Client credentials, replacing the placeholders with the values obtained in the [Auth0 Dashboard](https://manage.auth0.com/#/clients).

    ```xml
    <context-param>
        <param-name>com.auth0.domain</param-name>
        <param-value>{YOUR_AUTH0_DOMAIN}</param-value>
    </context-param>
    
    <context-param>
        <param-name>com.auth0.client_id</param-name>
        <param-value>{YOUR_AUTH0_CLIENT_ID}</param-value>
    </context-param>
    
    <context-param>
        <param-name>com.auth0.client_secret</param-name>
        <param-value>{YOUR_AUTH0_CLIENT_SECRET}</param-value>
    </context-param>
    ```

#### Allowed Settings
The list of required parameters for the servlet to initiate is:
 
**Required:**
* `com.auth0.redirect_on_success`: Defines the path to call after a successful redirection, when the user was just authenticated. Must be defined in the **local Servlet scope**.
* `com.auth0.redirect_on_error`: Defines the path to call after an error occurred while parsing the redirection data. Must be defined in the **local Servlet scope**.
* `com.auth0.redirect_on_authentication_error`: Defines the path to call when the user tries to access a protected endpoint without logging in first. Must be defined in the **local Filter scope**.
* `com.auth0.domain`: Auth0 Domain. Can be defined either in the local or the global Servlet context.
* `com.auth0.client_id`: Auth0 Client ID. Can be defined either in the local or the global Servlet context.
* `com.auth0.client_secret`: Auth0 Client Secret. It will also be used to verify the tokens with the `HS256` algorithm in case the Implicit Grant flow is enabled and no certificate file path is present. Can be defined either in the local or the global Servlet context.

**Optional:**
* `com.auth0.allow_post`: Whether requests with POST method are accepted or not. The value must be `true` to be considered enabled. Must be defined in the **local Servlet scope**.
* `com.auth0.use_implicit_grant`: Whether requests without an authorization code should be allowed or not. The value must be `true` to be considered enabled. Must be defined in the **local Servlet scope**.
* `com.auth0.certificate`: The path relative to the `webapp` folder where the PEM file containing the RSA Public Key or Certificate is located, in case the Implicit Grant flow is enabled. The `RS256` algorithm will be used to verify the tokens. Must be defined in the **local Servlet scope**.


#### Implicit Grant
**Code Grant is the default, safest and recommended method.** You can still use Implicit Grant if you enable it explicitly using the flag `com.auth0.use_implicit_grant`. Implicit Grant only works if the requests are made to the Servlet using the Http POST method. Enable the `com.auth0.allow_post` and make sure to request the login with the 'response_mode=form_post' parameter. 

The token validation will by default be performed using the **HS256** algorithm and the Client Secret. If you define the value `com.auth0.certificate`, the token validation will be performed using the **RS256** algorithm and the given RSA certificate.

If the Implicit Grant is disabled (default behaviour) and the Authorization Code is missing from the request parameters, an exception will raise.

## Usage

To Login the user it's recommended that you use the Auth0 [Hosted Login Page](https://auth0.com/docs/hosted-pages/login). With the [auth0-java](https://github.com/auth0/auth0-java) library you can generate the **authorize url** and call it to perform the login. A sample snippet of this step is shown below:

```java
public class LoginServlet extends HttpServlet {
    @Override
    protected void doGet(final HttpServletRequest req, final HttpServletResponse res) throws ServletException, IOException {
        AuthAPI authAPI = new AuthAPI("clientDomain", "clientId", "clientSecret");
        String state = ServletUtils.secureRandomString();
        ServletUtils.setSessionState(req, state); //Save the state for later verification
        String redirectUri = "https://mysite.com/callback";
        String authorizeUrl = authAPI
                .authorizeUrl(redirectUri)
                .withState(state)
                .build();
        res.sendRedirect(authorizeUrl);
    }
}
```

Note in the example above that a random state is set in the request and saved in the session, so that later when the redirect uri is hit we can validate it. Sending the `state` parameter is recommended to avoid CRF attacks.

After the user logs in successfully, the server will call the redirect uri with the `access_token`, `id_token` and depending on the requested **response_type**, an authorization `code` to exchange. The `Auth0RedirectServlet` servlet will check for errors and a valid incoming state. Next, it will try to parse the tokens from the request parameters and if a `code` needs to be exchanged, it will handle the exchange. Finally, it will call the Authentication API [/userInfo](https://auth0.com/docs/api/authentication#get-user-info) endpoint to obtain the user information associated to that access_token. If this call is successful, the **User Id** will be stored in the request session and the user will be considered authenticated. The User Id can be obtained by calling `ServletUtils.getSessionUserId(req)`. The servlet finally calls the `onSuccess` method passing the **Tokens** obtained in the login. The token values are **not saved** by the Servlet, if you want to keep them you'll need to handle the persistence yourself.

This servlet supports `GET` and `POST` calls to the redirect uri. A `POST` can be requested in the authorize url by adding the `response_mode=form_post` parameter to the query. Check the [Allowed Settings](#allowed-settings) section to learn how to enable it.


### Tokens class
The `Tokens` class holds the tokens obtained after a successful login. Note that not all of them are guaranteed to be available, as this depends on the **scope** requested on the `/authorize` call. The available methods are:
* `getAccessToken()`
* `getIdToken()`
* `getRefreshToken()`
* `getType()`
* `getExpiresIn()`


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

[Auth0](https://auth0.com)

## License

This project is licensed under the MIT license. See the [LICENSE](LICENSE.txt) file for more info.

