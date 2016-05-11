<!DOCTYPE html>
<html>
<head>
    <meta http-equiv="content-type" content="text/html; charset=utf-8"/>
    <title>Login</title>
    <script src="http://cdn.auth0.com/w2/auth0-6.7.js"></script>
    <script src="http://code.jquery.com/jquery.js"></script>
    <link rel="stylesheet" type="text/css" href="/css/bootstrap.css">
    <link rel="stylesheet" type="text/css" href="/css/signin.css">
</head>
<body>
<div class="container">
    
    <div id="enter-phone" class="form-signin">
        <h2 class="form-signin-heading">Phone</h2>
        <label for="phone-number" class="sr-only">Mobile Number</label>
        <input type="text" id="phone-number" class="form-control" placeholder="phone number" required="" autofocus="">
        <button id="phone-number-btn" class="btn btn-lg btn-primary btn-block">Send SMS</button>
    </div>

    <div id="enter-code" class="form-signin collapse">
        <h2 class="form-signin-heading">SMS Code</h2>
        <label for="code" class="sr-only">Code</label>
        <input type="text" id="code" class="form-control" placeholder="Code" required="">
        <button id="code-btn" class="btn btn-lg btn-primary btn-block">Submit Code</button>
    </div>

</div>

<jsp:include page="auth0.jsp" flush="true"/>

<script type="text/javascript">

    $('#phone-number-btn').click(function () {
        var phoneNumber = $('#phone-number').val();
        auth0.requestSMSCode({phoneNumber: phoneNumber}, function (err) {
            if (err) {
                console.error('Error sending SMS: ' + err.error_description);
                return;
            }
            // the request was successful and you should
            // receive the passcode to the specified phone
            $('#enter-phone').hide();
            $('#enter-code').show();
        });
    });

    $('#code-btn').click(function () {
        var phoneNumber = $('#phone-number').val();
        var code = $('#code').val();
        //submit the passcode to authenticate the phone
        auth0.verifySMSCode({state: '${state}', phoneNumber: phoneNumber, code: code}, function (err) {
            // this only gets called if there was an error
            if (err) {
                console.error("Error occurred: " + err.error_description);
                return;
            }
        });
    });

</script>

</body>
</html>
