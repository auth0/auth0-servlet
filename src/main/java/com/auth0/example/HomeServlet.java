package com.auth0.example;

import com.auth0.SessionUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class HomeServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {
        final String userId = SessionUtils.getAuth0UserId(req);
        if (userId != null) {
            req.setAttribute("userId", userId);
        }
        req.getRequestDispatcher("/WEB-INF/jsp/home.jsp").forward(req, res);
    }
}
