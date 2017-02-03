package com.auth0;

import com.auth0.client.auth.AuthAPI;
import com.auth0.exception.Auth0Exception;
import com.auth0.json.auth.TokenHolder;
import com.auth0.json.auth.UserInfo;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.Validate;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Properties;

import static java.util.Arrays.asList;

/**
 * The Servlet endpoint used as the callback handler in the OAuth 2.0 authorization code grant flow.
 * This servlet will be called from Auth0 with the authorization code after a successful login.
 */
public class Auth0RedirectServlet extends HttpServlet {

    @SuppressWarnings("WeakerAccess")
    protected AuthAPI authAPI;
    private Properties properties = new Properties();
    private String redirectOnSuccess;
    private String redirectOnFail;

    /**
     * Initialize this servlet with required configuration
     */
    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        redirectOnSuccess = readParameter("com.auth0.redirect_on_success", config);
        redirectOnFail = readParameter("com.auth0.redirect_on_error", config);
        for (String param : asList("com.auth0.client_id", "com.auth0.client_secret", "com.auth0.domain")) {
            properties.put(param, readParameter(param, config));
        }
        String clientId = (String) properties.get("com.auth0.client_id");
        String clientSecret = (String) properties.get("com.auth0.client_secret");
        String domain = (String) properties.get("com.auth0.domain");
        Validate.notNull(clientId);
        Validate.notNull(clientSecret);
        Validate.notNull(domain);
        authAPI = new AuthAPI(domain, clientId, clientSecret);
    }

    /**
     * Entrypoint for HTTP request
     * <p>
     * 1). Responsible for validating the request and ensuring the state value in session storage matches the state value passed to this endpoint.
     * 2). Exchanging the authorization code received with this HTTP request for auth0 tokens.
     * 3). Getting the user information associated to the id_token/access_token.
     * 4). Storing both tokens and user information into session storage.
     * 5). Clearing the stored state value.
     * 6). Handling success and any failure outcomes.
     */
    @Override
    public void doGet(HttpServletRequest req, HttpServletResponse res) throws IOException, ServletException {
        boolean validRequest = isValidRequest(req);
        SessionUtils.removeState(req);
        if (!validRequest) {
            onFailure(req, res, new IllegalStateException("Invalid state or error"));
            return;
        }

        String authorizationCode = req.getParameter("code");
        String redirectUri = req.getRequestURL().toString();
        Validate.notNull(authorizationCode);
        Validate.notNull(redirectUri);

        Tokens tokens = fetchTokens(authorizationCode, redirectUri);
        Auth0User auth0User = fetchUserInfo(tokens);
        SessionUtils.setTokens(req, tokens);
        SessionUtils.setAuth0User(req, auth0User);

        onSuccess(req, res);
    }

    /**
     * Actions / navigation to take when a request is deemed successful by this callback handler
     */
    @SuppressWarnings("WeakerAccess")
    protected void onSuccess(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {
        res.sendRedirect(req.getContextPath() + redirectOnSuccess);
    }

    /**
     * Actions / navigation to take when a request is deemed unsuccessful by this callback handler
     */
    @SuppressWarnings("WeakerAccess")
    protected void onFailure(HttpServletRequest req, HttpServletResponse res, Exception ex) throws ServletException, IOException {
        ex.printStackTrace();
        String redirectOnFailLocation = req.getContextPath() + redirectOnFail;
        res.sendRedirect(redirectOnFailLocation);
    }

    /**
     * Indicates whether the request is deemed valid
     *
     * @param req the http servlet request
     * @return boolean whether this request is deemed valid
     */
    private boolean isValidRequest(HttpServletRequest req) {
        return !hasError(req) && isValidState(req);
    }

    /**
     * Checks for the presence of an error in the http servlet request params
     *
     * @param req the http servlet request
     * @return boolean whether this http servlet request indicates an error was present
     */
    private boolean hasError(HttpServletRequest req) {
        return req.getParameter("error") != null;
    }

    /**
     * Indicates whether the nonce value in storage matches the nonce value passed
     * with the http servlet request
     *
     * @param req the http servlet request
     * @return boolean whether nonce value in storage matches the nonce value in the http request
     */
    private boolean isValidState(HttpServletRequest req) {
        String stateFromRequest = req.getParameter("state");
        String stateFromStorage = SessionUtils.getState(req);
        return stateFromRequest != null && stateFromRequest.equals(stateFromStorage);
    }

    /**
     * Attempts to get a property from the servlet context
     *
     * @param parameter the parameter name to lookup
     * @param config    the servlet config to search
     * @return the parameter value
     */
    private String readParameter(String parameter, ServletConfig config) {
        String initParam = config.getInitParameter(parameter);
        if (StringUtils.isNotEmpty(initParam)) {
            return initParam;
        }
        String servletContextInitParam = config.getServletContext().getInitParameter(parameter);
        if (StringUtils.isNotEmpty(servletContextInitParam)) {
            return servletContextInitParam;
        }
        throw new IllegalArgumentException(parameter + " needs to be defined");
    }

    private Tokens fetchTokens(String authorizationCode, String redirectUri) throws Auth0Exception {
        TokenHolder holder = authAPI
                .exchangeCode(authorizationCode, redirectUri)
                .execute();
        return new Tokens(holder.getAccessToken(), holder.getIdToken(), holder.getRefreshToken(), holder.getTokenType(), holder.getExpiresIn());
    }

    private Auth0User fetchUserInfo(Tokens tokens) throws Auth0Exception {
        Validate.notNull(tokens);
        UserInfo info = authAPI
                .userInfo(tokens.getAccessToken())
                .execute();
        return new Auth0User(info);
    }

}
