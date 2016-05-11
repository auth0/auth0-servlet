<script type="text/javascript">
    var auth0 = new Auth0({
        domain: '<%= application.getInitParameter("auth0.domain") %>',
        clientID: '<%= application.getInitParameter("auth0.client_id") %>',
        callbackURL: '<%= request.getAttribute("baseUrl") + "/callback" %>'
    });
</script>