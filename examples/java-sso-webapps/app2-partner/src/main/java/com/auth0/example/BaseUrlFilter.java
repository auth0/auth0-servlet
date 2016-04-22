package com.auth0.example;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

public class BaseUrlFilter implements Filter {

    protected static String buildUrlStr(final HttpServletRequest request) {
        if (request == null) {
            throw new NullPointerException("request cannot be null");
        }
        final String scheme = request.getScheme();
        final String serverName = request.getServerName();
        final int serverPort = request.getServerPort();
        final StringBuffer url = new StringBuffer();
        url.append(scheme).append("://").append(serverName);
        if ((serverPort != 80) && (serverPort != 443)) {
            url.append(":").append(serverPort);
        }
        return url.toString();
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        final String baseUrl = buildUrlStr((HttpServletRequest) request);
        request.setAttribute("baseUrl", baseUrl);
        chain.doFilter(request, response);
    }

    @Override
    public void destroy() {
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
    }

}
