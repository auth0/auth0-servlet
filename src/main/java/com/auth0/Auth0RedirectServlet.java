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

/**
 * The Servlet endpoint used as the callback handler in the OAuth 2.0 authorization code grant flow.
 * This servlet will be called from Auth0 with the authorization code after a successful login.
 */
public class Auth0RedirectServlet extends HttpServlet {

    private AuthAPI authAPI;
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
        String clientId = readParameter("com.auth0.client_id", config);
        String clientSecret = readParameter("com.auth0.client_secret", config);
        String domain = readParameter("com.auth0.domain", config);
        Validate.notNull(clientId);
        Validate.notNull(clientSecret);
        Validate.notNull(domain);

        authAPI = new AuthAPI(domain, clientId, clientSecret);
    }

    /**
     * Auth0 server will call the redirect_uri with the tokens using the GET method.
     *
     * @param req the received request with the tokens in the parameters.
     * @param res the response to send back to the server.
     * @throws IOException
     * @throws ServletException
     */
    @Override
    public void doGet(HttpServletRequest req, HttpServletResponse res) throws IOException, ServletException {
        parseRedirectRequest(req, res);
    }

    /**
     * Auth0 server will call the redirect_uri with the tokens using the POST method when the authorize_url included the 'response_mode=form_post' value.
     *
     * @param req the received request with the tokens in the parameters.
     * @param res the response to send back to the server.
     * @throws IOException
     * @throws ServletException
     */
    @Override
    public void doPost(HttpServletRequest req, HttpServletResponse res) throws IOException, ServletException {
        parseRedirectRequest(req, res);
    }

    /**
     * Getter for the {@link AuthAPI} client used to call Auth0 Server for Authentication.
     *
     * @return the instance of the client.
     */
    @SuppressWarnings("unused")
    protected AuthAPI getAuthAPIClient() {
        return authAPI;
    }

    /**
     * Actions to take when Auth0 tokens are obtained.
     *
     * @param tokens the current session tokens.
     */
    @SuppressWarnings({"WeakerAccess", "unused"})
    protected void onAuth0TokensObtained(Tokens tokens) {
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
     * Entrypoint for HTTP request
     * <p>
     * 1). Responsible for validating the request and ensuring the state value in session storage matches the state value passed to this endpoint.
     * 2). Exchanging the authorization code received with this HTTP request for auth0 tokens.
     * 3). Getting the user information associated to the id_token/access_token.
     * 4). Storing both tokens and user information into session storage.
     * 5). Clearing the stored state value.
     * 6). Handling success and any failure outcomes.
     */
    private void parseRedirectRequest(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {
        boolean validRequest = isValidRequest(req);
        SessionUtils.removeState(req);
        if (!validRequest) {
            onFailure(req, res, new IllegalStateException("Invalid state or error"));
            return;
        }

        Tokens tokens = tokensFromRequest(req);
        String authorizationCode = req.getParameter("code");
        if (authorizationCode != null) {
            String redirectUri = req.getRequestURL().toString();
            Tokens latestTokens = exchangeCodeForTokens(authorizationCode, redirectUri);
            tokens = mergeTokens(tokens, latestTokens);
        }

        String userId = fetchUserId(tokens);
        if (userId == null) {
            onFailure(req, res, new IllegalStateException("Couldn't obtain the User Id."));
            return;
        }

        SessionUtils.setAuth0UserId(req, userId);
        onAuth0TokensObtained(tokens);
        onSuccess(req, res);
    }

    private Tokens tokensFromRequest(HttpServletRequest req) throws Auth0Exception {
        Long expiresIn = req.getParameter("expires_in") == null ? null : Long.parseLong(req.getParameter("expires_in"));
        return new Tokens(req.getParameter("access_token"), req.getParameter("id_token"), req.getParameter("refresh_token"), req.getParameter("token_type"), expiresIn);
    }

    private Tokens exchangeCodeForTokens(String authorizationCode, String redirectUri) throws Auth0Exception {
        Validate.notNull(authorizationCode);
        Validate.notNull(redirectUri);

        TokenHolder holder = authAPI
                .exchangeCode(authorizationCode, redirectUri)
                .execute();
        return new Tokens(holder.getAccessToken(), holder.getIdToken(), holder.getRefreshToken(), holder.getTokenType(), holder.getExpiresIn());
    }

    /**
     * Indicates whether the request is deemed valid
     *
     * @param req the http servlet request
     * @return boolean whether this request is deemed valid
     */
    private boolean isValidRequest(HttpServletRequest req) {
        return !hasError(req) && hasValidState(req);
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
     * Indicates whether the state value in storage matches the state value passed
     * with the http servlet request
     *
     * @param req the http servlet request
     * @return boolean whether state value in storage matches the state value in the http request
     */
    private boolean hasValidState(HttpServletRequest req) {
        String stateFromRequest = req.getParameter("state");
        String stateFromStorage = SessionUtils.getState(req);
        return stateFromRequest != null && stateFromRequest.equals(stateFromStorage);
    }

    private String fetchUserId(Tokens tokens) throws Auth0Exception {
        Validate.notNull(tokens.getAccessToken());

        UserInfo info = authAPI
                .userInfo(tokens.getAccessToken())
                .execute();
        return info.getValues().containsKey("sub") ? (String) info.getValues().get("sub") : null;
    }

    /**
     * Used to keep the best version of each token included in Tokens.
     *
     * @param tokens       the first obtained tokens.
     * @param latestTokens the latest obtained tokens, usually better than the first.
     * @return a merged version of Tokens using the latest tokens when possible.
     */
    private Tokens mergeTokens(Tokens tokens, Tokens latestTokens) {
        String accessToken = latestTokens.getAccessToken() != null ? latestTokens.getAccessToken() : tokens.getAccessToken();
        String idToken = latestTokens.getIdToken() != null ? latestTokens.getIdToken() : tokens.getIdToken();
        String refreshToken = latestTokens.getRefreshToken() != null ? latestTokens.getRefreshToken() : tokens.getRefreshToken();
        String type = latestTokens.getType() != null ? latestTokens.getType() : tokens.getType();
        Long expiresIn = latestTokens.getExpiresIn() != null ? latestTokens.getExpiresIn() : tokens.getExpiresIn();
        return new Tokens(accessToken, idToken, refreshToken, type, expiresIn);
    }

    /**
     * Attempts to get a property from the servlet context
     *
     * @param parameter the parameter name to lookup
     * @param config    the servlet config to search
     * @return the parameter value
     */
    private static String readParameter(String parameter, ServletConfig config) {
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

}
