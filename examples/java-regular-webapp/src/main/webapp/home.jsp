<%@ page import="com.auth0.Auth0User" %>
<!DOCTYPE html>
<html>
  <head>
    <meta http-equiv="content-type" content="text/html; charset=utf-8" />
    <title>Welcome</title>
      <script src="http://code.jquery.com/jquery.js"></script>
  </head>
  <body>

  <script type="text/javascript">

  <%!
    // Converts a relative path into a full path
    public String buildUrl(HttpServletRequest request, String relativePath) {
      final String scheme = request.getScheme();
      final String serverName = request.getServerName();
      final int serverPort = request.getServerPort();
      final String contextPath = request.getContextPath();
      // Reconstruct original requesting URL
      final StringBuffer url =  new StringBuffer();
      url.append(scheme).append("://").append(serverName);
      if ((serverPort != 80) && (serverPort != 443)) {
        url.append(":").append(serverPort);
      }
      url.append(contextPath).append(relativePath);
      return url.toString();
    }
  %>

  <% Auth0User user = (Auth0User) request.getAttribute("user"); %>

  function logout() {
    return window.location = '<%= buildUrl(request, "/logout") %>'
  }

  </script>

  <h1>Welcome</h1>
  <img src="<%=user.getPicture()%>"/>
  <br />
  Hello <%=user.getName()%>!</p>
  <p>Your nickname is: <%=user.getNickname()%></p>

  <button id="logout">Logout</button>

  <script>
    $("#logout").click(function(e) {
      e.preventDefault();
      logout();
    });

  </script>

  </body>
</html>
