<%@ page import="com.auth0.Auth0User" %>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Home Page</title>
    <link rel="stylesheet" type="text/css" href="/css/bootstrap.css">
    <link rel="stylesheet" type="text/css" href="/css/jumbotron-narrow.css">
    <script src="http://cdn.auth0.com/w2/auth0-6.7.js"></script>
    <script src="http://code.jquery.com/jquery.js"></script>
</head>

<body>

<jsp:include page="auth0.jsp" flush="true"/>

<script type="text/javascript">
    <% Auth0User user = (Auth0User) request.getAttribute("user"); %>
</script>

<div class="container">
    <div class="header clearfix">
        <nav>
            <ul class="nav nav-pills pull-right">
                <li role="presentation" class="active" id="home"><a href="#">Home</a></li>
                <% if ((Boolean)request.getAttribute("linkDropBox")) { %>
                    <li role="presentation" id="link-dropbox"><a href="#">Link DropBox</a></li>
                <% } %>
                <li role="presentation" id="logout"><a href="#">Logout</a></li>
            </ul>
        </nav>
        <h3 class="text-muted">App.com</h3>
    </div>
    <div class="jumbotron">
        <h3>Hello <%=user.getName()%>!</h3>
        <p class="lead">Your nickname is: <%=user.getNickname()%></p>
        <p class="lead">Your user id is: <%=user.getUserId()%></p>
        <p><img class="avatar" src="<%=user.getPicture()%>"/></p>
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
        <p> &copy; 2016 Company Inc</p>
    </footer>

</div>

<script type="text/javascript">

    <% if ((Boolean)request.getAttribute("linkDropBox")) { %>

        $('#link-dropbox').click(function () {
            $("#home").removeClass("active")
            $("#logout").removeClass("active")
            $("#link-dropbox").addClass("active")
            auth0.login({
                connection: 'dropbox',
                scope: 'openid name email picture',
                state: '${state}'
            }, function (err) {
                // this only gets called if there was an error
                console.error('Error logging in: ' + err);
            });
        });

    <% } %>

    $("#logout").click(function(e) {
        e.preventDefault();
        $("#home").removeClass("active")
        $("#link-dropbox").removeClass("active")
        $("#logout").addClass("active")
        return auth0.logout({
            client_id: '<%= application.getInitParameter("auth0.client_id") %>',
            returnTo: '<%= request.getAttribute("baseUrl") + "/logout" %>'
        });
    });

</script>

</body>
</html>