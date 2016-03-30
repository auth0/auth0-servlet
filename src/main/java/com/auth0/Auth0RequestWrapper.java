package com.auth0;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import java.security.Principal;
import java.util.Map;
import java.util.HashMap;

public class Auth0RequestWrapper extends HttpServletRequestWrapper {
    String idToken;
    HttpServletRequest realRequest;
    private Auth0User user;
    private Map<String, String> customHeaderMap = null;


    public Auth0RequestWrapper(Auth0User user, HttpServletRequest request) {
        super(request);
        this.user = user;
        this.realRequest = request;
        this.customHeaderMap = new HashMap<String, String>();
    }

    public void addHeader(String name,String value){
        customHeaderMap.put(name, value);
    }

    @Override
    public Principal getUserPrincipal() {
        if (this.user == null) {
            return realRequest.getUserPrincipal();
        }

        return user;
    }

    @Override
    public String getParameter(String name) {
        String paramValue = super.getParameter(name);
        if (paramValue == null) {
            paramValue = customHeaderMap.get(name); //The custom header is added to the querystring.
        }
        return paramValue;
    }

}