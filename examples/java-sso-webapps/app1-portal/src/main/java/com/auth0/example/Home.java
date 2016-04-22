package com.auth0.example;

import com.auth0.Auth0User;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class Home extends HttpServlet {

    private static final Logger logger = LogManager.getLogger(Home.class);

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        logger.debug("Home");
        final Auth0User user = Auth0User.get(request);
        request.setAttribute("isAuthenticated", (user != null) ? true : false);
        if (user != null) {
            request.setAttribute("user", user);
        }
        request.getRequestDispatcher("/home.jsp").forward(request, response);
    }
}
