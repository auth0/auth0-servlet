package com.auth0.example;

import com.auth0.Auth0User;
import com.auth0.NonceGenerator;
import com.auth0.NonceStorage;
import com.auth0.RequestNonceStorage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class Home extends HttpServlet {

    private static final Logger logger = LogManager.getLogger(Home.class);

    private final NonceGenerator nonceGenerator = new NonceGenerator();

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {

        logger.debug("Home");
        logger.debug("Request GetServletPath: " + request.getServletPath());

        final String baseUrl = Helpers.buildUrlStr(request);
        request.setAttribute("baseUrl", baseUrl);
        final NonceStorage nonceStorage = new RequestNonceStorage(request);
        final String nonce = nonceGenerator.generateNonce();
        nonceStorage.setState(nonce);
        request.setAttribute("state", "nonce=" + nonce);

        final String authorizationErrorDescription = request.getParameter("error_description");
        if (authorizationErrorDescription != null) {
            request.setAttribute("authorizationErrorDescription", authorizationErrorDescription);
            request.setAttribute("error", authorizationErrorDescription);
        }
        // check if logged in..
        final Auth0User user = Auth0User.get(request);
        request.setAttribute("isAuthenticated", (user != null) ? true : false);
        if (user != null) {
            request.setAttribute("user", user);
        }
        request.getRequestDispatcher("/home.jsp").forward(request, response);
    }

}
