package com.auth0.example;


import com.auth0.lib.Auth0MVC;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;

public class LoginServlet extends HttpServlet {

    private Auth0MVC auth0MVC;

    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        try {
            auth0MVC = Auth0MVCProvider.getInstance(config);
        } catch (UnsupportedEncodingException e) {
            throw new ServletException("Couldn't create the Auth0MVC instance. Check the configuration.", e);
        }
    }

    @Override
    protected void doGet(final HttpServletRequest req, final HttpServletResponse res) throws ServletException, IOException {
        String callbackPath = getServletConfig().getInitParameter("com.auth0.onLoginRedirectTo");
        String redirectUri = req.getScheme() + "://" + req.getServerName() + ":" + req.getServerPort() + callbackPath;

        String authorizeUrl = auth0MVC.buildAuthorizeUrl(req, redirectUri);
        res.sendRedirect(authorizeUrl);
    }

}
