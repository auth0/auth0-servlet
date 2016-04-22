<%@ page import="com.auth0.Auth0User" %>
<!DOCTYPE html>
<html>
<head>
    <meta http-equiv="content-type" content="text/html; charset=utf-8" />
    <title>Partner Home Page</title>
    <link rel="stylesheet" type="text/css" href="/css/bootstrap.css">
    <link rel="stylesheet" type="text/css" href="/css/jumbotron-narrow.css">
    <script src="http://cdn.auth0.com/w2/auth0-6.7.js"></script>
    <script src="http://code.jquery.com/jquery.js"></script>
</head>
<body>

<script>
    // hide the page in case there is an SSO session (to avoid flickering)
    $('body').hide();
</script>

<script type="text/javascript">

    var auth0 = new Auth0({
        domain:'<%= application.getInitParameter("auth0.domain") %>',
        clientID:'<%= application.getInitParameter("auth0.client_id") %>',
        callbackURL:'<%= request.getAttribute("baseUrl") + "/callback" %>'
    });

    var authenticated = <%= (Boolean) request.getAttribute("isAuthenticated") %>
    <% Auth0User user = (Auth0User) request.getAttribute("user"); %>

    function auth0Logout() {
        var options = {
            returnTo: '<%= request.getAttribute("baseUrl") + "/logout" %>'
        }
        return auth0.logout(options);
    }

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
                $('body').show();
            }
        } else {

            <% if ((Boolean) request.getAttribute("isAuthenticated")) { %>
                // user is logged in locally, but no SSO session exists -> log them out locally
                window.location = '<%= request.getAttribute("baseUrl") + "/logout" %>';
            <% } else { %>

            // user is not logged in locally and no SSO session exists -> send them to the partner login page
            window.location = '<%= application.getInitParameter("auth0.partnerLoginUrl") %>?externalReturnUrl=' +
                    encodeURIComponent(window.location);
            <% } %>
        }
    });


</script>

<% if (user != null) { %>

<div class="container">
    <div class="header clearfix">
        <nav>
            <ul class="nav nav-pills pull-right">
                <li role="presentation" class="active" id="home"><a href="#">Home</a></li>
                <li role="presentation" id="logout"><a href="#">Logout</a></li>
            </ul>
        </nav>
        <h3 class="text-muted">App2.com - Partner Site</h3>
    </div>
    <div class="jumbotron">
        <h3>Hello <%=user.getName()%>!</h3>
        <p class="lead">Your nickname is: <%=user.getNickname()%></p>
        <p><img src="<%=user.getPicture()%>"/></p>
    </div>
    <div class="row marketing">
        <div class="col-lg-6">
            <h4>Subheading</h4>
            <p>Donec id elit non mi porta gravida at eget metus. Maecenas faucibus mollis interdum.</p>

            <h4>Subheading</h4>
            <p>Morbi leo risus, porta ac consectetur ac, vestibulum at eros. Cras mattis consectetur purus sit amet
                fermentum.</p>

        </div>

        <div class="col-lg-6">
            <h4>Subheading</h4>
            <p>Donec id elit non mi porta gravida at eget metus. Maecenas faucibus mollis interdum.</p>

            <h4>Subheading</h4>
            <p>Morbi leo risus, porta ac consectetur ac, vestibulum at eros. Cras mattis consectetur purus sit amet
                fermentum.</p>

        </div>
    </div>

    <footer class="footer">
        <p> &copy; 2016 Company, Inc.</p>
    </footer>

</div>

<% } %>

<script>
    $("#logout").click(function(e) {
        e.preventDefault();
        $("#home").removeClass("active")
        $("#logout").addClass("active")
        auth0Logout();
    });
</script>

</body>
</html>
