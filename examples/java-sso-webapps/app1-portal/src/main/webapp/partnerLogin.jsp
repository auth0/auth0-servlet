<%@ page import="com.auth0.Auth0User" %>
<!DOCTYPE html>
<html>
  <head>
    <meta http-equiv="content-type" content="text/html; charset=utf-8" />
    <title>Login</title>
      <script src="http://cdn.auth0.com/w2/auth0-6.7.js"></script>
      <script src="http://code.jquery.com/jquery.js"></script>
      <link rel="stylesheet" type="text/css" href="/css/bootstrap.min.css">
      <link rel="stylesheet" type="text/css" href="/css/signin.css">
  </head>
  <body>

  <div class="container">
      <div class="form-signin">
          <h2 class="form-signin-heading">Partner - Sign In</h2>
          <label for="email" class="sr-only">Email address</label>
          <input type="email" id="email" class="form-control" placeholder="Email address" required="" autofocus="">
          <label for="password" class="sr-only">Password</label>
          <input type="password" id="password" class="form-control" placeholder="Password" required="">
          <button id="signin-db" class="btn btn-lg btn-primary btn-block">Sign in</button>
      </div>
  </div>

  <jsp:include page="auth0.jsp" flush="true"/>

  <script type="text/javascript">

     $('body').show();

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
             console.error('Error logging in using partner login page: ' + err);
         });
     });

    </script>
  </body>
</html>
