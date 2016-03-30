<!DOCTYPE html>
<html>
  <head>
    <meta http-equiv="content-type" content="text/html; charset=utf-8" />
    <title>Login</title>
    <script src="https://cdn.auth0.com/js/lock-9.0.min.js"></script>
  </head>
  <body>
    <script type="text/javascript">

     <%!

         // Converts a relative path into a full path
         // Taken from http://stackoverflow.com/posts/5212336/revisions
        public String buildUrl(HttpServletRequest request, String relativePath) {


         String scheme      =    request.getScheme();        // http
         String serverName  =    request.getServerName();    // hostname.com
         int serverPort     =    request.getServerPort();    // 80
         String contextPath =    request.getContextPath();   // /mywebapp

         // Reconstruct original requesting URL
         StringBuffer url =  new StringBuffer();
         url.append(scheme).append("://").append(serverName);

         if ((serverPort != 80) && (serverPort != 443)) {
             url.append(":").append(serverPort);
         }

         url.append(contextPath).append(relativePath);

         return url.toString();

         }
      %>
      
      var lock = new Auth0Lock('<%= application.getInitParameter("auth0.client_id") %>', '<%= application.getInitParameter("auth0.domain") %>');
      
      function signin() {
        lock.show({
            callbackURL: '<%= buildUrl(request, "/callback") %>'
          , responseType: 'code'
          , authParams: {
              state: '${state}'
            , scope: 'openid name email picture'
            }
        });
      }
    </script>
    <% if ( request.getParameter("error") != null ) { %>
        <%-- TODO Escape and encode ${param.error} properly. It can be done using jstl c:out. --%>
        <span style="color: red;">${param.error}</span>
    <% } %>
    <button onclick="signin()">Login</button>
  </body>
</html>
