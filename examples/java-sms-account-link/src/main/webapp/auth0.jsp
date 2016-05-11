<script type="text/javascript">
    var auth0 = new Auth0({
        clientID: '<%= application.getInitParameter("auth0.client_id") %>',
        domain: '<%= application.getInitParameter("auth0.domain") %>',
        callbackURL: '<%= request.getAttribute("baseUrl") + "/callback" %>'
    });
</script>