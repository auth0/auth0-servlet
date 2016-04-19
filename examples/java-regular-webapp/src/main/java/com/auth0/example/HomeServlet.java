package com.auth0.example;

import com.auth0.Auth0User;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class HomeServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        Auth0User user = Auth0User.get(request);
        if (user != null) {
            request.setAttribute("user", user);
        }
        request.getRequestDispatcher("/home.jsp").forward(request, response);
    }
}
