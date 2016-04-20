<%@ page import="com.auth0.Auth0User" %>
<!DOCTYPE html>
<html>
  <head>
    <meta http-equiv="content-type" content="text/html; charset=utf-8" />
    <title>Login</title>
      <script src="http://cdn.auth0.com/w2/auth0-6.7.js"></script>
      <script src="http://code.jquery.com/jquery.js"></script>
      <link rel="stylesheet" type="text/css" href="/css/bootstrap.css">
      <link rel="stylesheet" type="text/css" href="/css/signin.css">
  </head>
  <body>
    <script>
        // hide the page in case there is an SSO session (to avoid flickering)
        $('body').hide();
    </script>

    <div class="container">
        <div class="form-signin">
            <h2 class="form-signin-heading">Main - Sign In</h2>
            <label for="email" class="sr-only">Email address</label>
            <input type="email" id="email" class="form-control" placeholder="Email address" required="" autofocus="">
            <label for="password" class="sr-only">Password</label>
            <input type="password" id="password" class="form-control" placeholder="Password" required="">
            <button id="signin-db" class="btn btn-lg btn-primary btn-block">Sign in</button>
        </div>
    </div>

    <script type="text/javascript">

    var auth0 = new Auth0({
        domain: '<%= application.getInitParameter("auth0.domain") %>',
        clientID: '<%= application.getInitParameter("auth0.client_id") %>',
        callbackURL: '<%= request.getAttribute("baseUrl") + "/callback" %>'
    });

     // check SSO status
     auth0.getSSOData(function (err, data) {

         if (data && data.sso === true) {
             console.log('SSO: an Auth0 SSO session already exists');

             var loggedInUserId = <%= (Boolean) request.getAttribute("isAuthenticated") ? "'" + ((Auth0User) request.getAttribute("user")).getUserId() + "'" : "null" %>;

             // perform an SSO login if user is not logged in locally or they are but they're logged in as a different user
             if (!loggedInUserId || loggedInUserId !== data.lastUsedUserID) {

                 auth0.login({
                     connection: '<%= application.getInitParameter("auth0.connection") %>',
                     scope: 'openid name email picture',
                     state: '${state}'
                 }, function (err) {
                     // this only gets called if there was a login error
                     console.error('Error logging in: ' + err);
                 });

             } else {
                 // have SSO session and valid user - send to portal/home
                 window.location = '<%= request.getAttribute("baseUrl") + "/portal/home" %>';
             }
         } else {
             <% if ((Boolean) request.getAttribute("isAuthenticated")) { %>
                 // user is logged in locally, but no SSO session exists -> log them out locally
                 window.location ='<%= request.getAttribute("baseUrl") + "/logout" %>';
             <% } else { %>
                 $('body').show();
                 // user is not logged in locally and no SSO session exists -> display login page
                 //trigger login with a db connection
                 $('#signin-db').on('click', function() {
                     auth0.login({
                         connection: '<%= application.getInitParameter("auth0.connection") %>',
                         username: $('#email').val(),
                         password: $('#password').val(),
                         sso: true,
                         scope: 'openid name email picture',
                         state: '${state}'
                     }, function (err) {
                         // this only gets called if there was a login error
                         console.error('Error logging in: ' + err);
                     });
                 });

             <% } %>
         }
     });

    </script>
  </body>
</html>
