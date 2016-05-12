<!DOCTYPE html>
<html>
<head>
    <meta http-equiv="content-type" content="text/html; charset=utf-8"/>
    <title>Login</title>
    <script src="http://code.jquery.com/jquery.js"></script>
    <script src="http://cdn.auth0.com/w2/auth0-6.7.js"></script>
    <script src="/js/jquery.growl.js" type="text/javascript"></script>
    <link rel="stylesheet" type="text/css" href="/css/bootstrap.css"/>
    <link rel="stylesheet" type="text/css" href="/css/signin.css"/>
    <link rel="stylesheet" type="text/css" href="/css/jquery.growl.css"/>
</head>
<body>
<div class="container">
    <div id="enter-email" class="form-signin">
        <h2 class="form-signin-heading">Email</h2>
        <label for="email" class="sr-only">Email</label>
        <input type="text" id="email" class="form-control" placeholder="email" required="" autofocus="">
        <button id="send-email-btn" class="btn btn-lg btn-primary btn-block">Send</button>
    </div>
</div>

<script type="text/javascript">

    $(function () {
        $.growl({title: "Welcome!", message: "Please log in"});
    });

    var auth0 = new Auth0({
        clientID: '<%= application.getInitParameter("auth0.client_id") %>',
        domain: '<%= application.getInitParameter("auth0.domain") %>',
        callbackURL: '<%= request.getAttribute("baseUrl") + "/mcallback" %>'
    });

    $('#send-email-btn').click(function () {
        var email = $('#email').val();
        auth0.requestMagicLink({
            authParams: {
                state: '${state}'
            },
            email: email,
            send: 'link'
        }, function (err) {
            // this only gets called if there was an error ??
            if (err) {
                alert('Error sending e-mail: ' + err.error_description);
                return;
            }
            // the request was successful and email sent
            $('.enter-email').hide();
            $.growl.notice({message: "Please check your inbox for email with link to signin"});
        });
    });

</script>

</body>
</html>
