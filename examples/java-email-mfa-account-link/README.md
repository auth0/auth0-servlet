## Simple Application demonstrating Passwordless authentication and subsequent MFA opt-in & Social Connection Upgrade

So you basically:

```
1) start with passwordless, using email magic link
2) when the user is ready to create their dropbox account, they opt to "sign up" by selecting "Link Dropbox"
3). when the user is ready they can opt-in to Multi-Factor authentication - in this sample using [duo](https://duo.com/)
```

### Prerequisites

In order to run this example you will need to have Java 8 and Maven installed. You can install Maven with [brew](http://brew.sh/):

```sh
brew install maven
```

Check that your maven version is 3.0.x or above:
```sh
mvn -v
```

### Setup

Create an [Auth0 Account](https://auth0.com) (if not already done so - free!).


#### From the Auth0 Dashboard

Create an application - for the purposes of this sample - `app`

Ensure you add the following to the settings.

Allowed Callback URLs:

```
http://localhost:3099/callback
http://localhost:3099/mcallback
```

Ensure you add the following to the settings.

Allowed Logout URLs:

```
http://localhost:3099/logout
```

Now, please ensure you set up both a

```
Passwordless Email Connection (Connections -> Passwordless -> Email)
Dropbox Social Connection (Connections -> Social -> Dropbox)
```

Both of these connection types NEED to be associated with the application you have created - `app`


Next, enable MFA - Multi-Factor Authentication, and configure with the following - supplying your own values:

```
function (user, context, callback) {
  var CLIENTS_WITH_MFA = ['{YOUR_CLIENT_ID}'];
  // run only for the specified clients
  if (CLIENTS_WITH_MFA.indexOf(context.clientID) !== -1) {
    // we only want users whose app_metadata is updated with mfa flag = true to use this
    if (user.app_metadata && (user.app_metadata.mfa === true)){
      context.multifactor = {
        //required
        provider: 'duo',
        ikey: '{INTEGRATION_KEY}',
        skey: '{SECRET_KEY}',
        host: '{API_HOSTNAME}',

         ignoreCookie: false,

      };
    }
  }
  callback(null, user, context);
}
```

You will have to set up a (free) account with Duo Security, to obtain the integration key, secret key, and api hostname.

Screenshot below of how this looks:

![](img/duo_app.jpg)

That's it for the Dashboard setup!


### Update configuration information

Enter your:

`client_id`, `client_secret`, `domain` and `appMetadata` information into `src/main/webapp/WEB-INF/web.xml`

For the `appMetadata` token, you shall need to visit our [management api page](https://auth0.com/docs/api/management/v2#!/Users/patch_users_by_id)

Ensure you select `update:users_app_metadata` grant.

![](img/patch_user1.jpg)

Copy the generated management token

![](img/patch_user2.jpg)


### Build and Run

In order to build and run the project you must execute:
```sh
mvn clean install tomcat7:run
```

Then, go to [http://localhost:3099/login](http://localhost:3099/login).

---

### Here are some screenshots of the overall flow (minus the Growler notifications!):


#### 1.Login

![](img/1.login.jpg)

#### 2.Email

![](img/2.email.jpg)

#### 3. Home

![](img/3.home.jpg)

#### 4. Dropbox Link Accounts

![](img/4.dropbox.jpg)

#### 5. Home

![](img/5.home.jpg)

#### 6. Login

![](img/6.login.jpg)

#### 7. Mail

![](img/7.mail.jpg)

#### 8. MFA with Duo

![](img/8.mfa.jpg)

#### 9. MFA with Duo

![](img/9.mfa.jpg)

#### 10. MFA with Duo

![](img/10.mfa.jpg)

#### 11. MFA with Duo

![](img/11.mfa.jpg)

#### 12. MFA with Duo

![](img/12.mfa.jpg)

#### 13. MFA with Duo

![](img/13.mfa.jpg)

#### 14. MFA with Duo

![](img/14.mfa.jpg)

#### 15. Home

![](img/15.home.jpg)

#### 16. User Profile upon completion

![](img/user_info.jpg)



---


## License

The MIT License (MIT)

Copyright (c) 2016 AUTH10 LLC

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
