package com.auth0.example;

import com.auth0.jwt.JWT;
import com.auth0.lib.SessionUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class HomeServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {
        final String accessToken = (String) SessionUtils.get(req, "accessToken");
        if (accessToken != null) {
            req.setAttribute("userId", JWT.decode(accessToken).getSubject());
        }
        req.getRequestDispatcher("/WEB-INF/jsp/home.jsp").forward(req, res);
    }
}
