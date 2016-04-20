package com.auth0.example;

import com.auth0.Auth0User;
import com.auth0.NonceStorage;
import com.auth0.RequestNonceStorage;
import com.auth0.Tokens;
import org.apache.commons.lang3.Validate;
import us.monoid.json.JSONObject;
import us.monoid.web.JSONResource;
import us.monoid.web.Resty;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.Map;
import java.util.Properties;

import static java.util.Arrays.asList;
import static us.monoid.web.Resty.content;

public class MyAuth0ServletCallback extends HttpServlet {

    private Properties properties = new Properties();
    private String redirectOnSuccess;
    private String redirectOnFail;

    /**
     * Fetch properties to be used. User is encourage to override this method.
     * <p>
     * Auth0 uses the ServletContext parameters:
     * <p>
     * <dl>
     * <dt>auth0.client_id</dd>
     * <dd>Application client id</dd>
     * <dt>auth0.client_secret</dt>
     * <dd>Application client secret</dd>
     * <dt>auth0.domain</dt>
     * <dd>Auth0 domain</dd>
     * </dl>
     * <p>
     * Auth0ServletCallback uses these ServletConfig parameters:
     * <p>
     * <dl>
     * <dt>auth0.redirect_on_success</dt>
     * <dd>Where to send the user after successful login.</dd>
     * <dt>auth0.redirect_on_error</dt>
     * <dd>Where to send the user after failed login.</dd>
     * </dl>
     */
    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);

        redirectOnSuccess = readParameter("auth0.redirect_on_success", config);

        redirectOnFail = readParameter("auth0.redirect_on_error", config);

        for (String param : asList("auth0.client_id", "auth0.client_secret",
                "auth0.domain")) {
            properties.put(param, readParameter(param, config));
        }
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        if (isValidRequest(req, resp)) {
            try {
                Tokens tokens = fetchTokens(req);
                Auth0User user = fetchUser(tokens);
                store(tokens, user, req);
                // clear nonce here
                final NonceStorage nonceStorage = new RequestNonceStorage(req);
                nonceStorage.setState(null);
                onSuccess(req, resp);
            } catch (IllegalArgumentException ex) {
                onFailure(req, resp, ex);
            } catch (IllegalStateException ex) {
                onFailure(req, resp, ex);
            }
        } else {
            onFailure(req, resp, new IllegalStateException("Invalid state or error"));
        }
    }

    protected void onSuccess(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        final String externalReturnUrl = (String) req.getAttribute("externalReturnUrl");
        if (externalReturnUrl != null) {
            resp.sendRedirect(externalReturnUrl);
        } else {
            resp.sendRedirect(req.getContextPath() + redirectOnSuccess);
        }
    }

    protected void onFailure(HttpServletRequest req, HttpServletResponse resp,
                             Exception ex) throws ServletException, IOException {
        if (ex != null) {
            ex.printStackTrace();
        }
        final String externalReturnUrl = (String) req.getAttribute("externalReturnUrl");
        if (externalReturnUrl != null) {
            //TODO - improve error reporting here in safe way
            resp.sendRedirect(externalReturnUrl + "?error_description=Error in request");
        } else {
            resp.sendRedirect(req.getContextPath() + redirectOnFail + "?"
                    + req.getQueryString());
        }

    }

    protected void store(Tokens tokens, Auth0User user, HttpServletRequest req) {
        HttpSession session = req.getSession();

        // Save tokens on a persistent session
        session.setAttribute("auth0tokens", tokens);
        session.setAttribute("user", user);
    }

    private Tokens fetchTokens(HttpServletRequest req) throws IOException {
        String authorizationCode = getAuthorizationCode(req);
        Resty resty = createResty();

        String tokenUri = getTokenUri();

        JSONObject json = new JSONObject();
        try {
            json.put("client_id", properties.get("auth0.client_id"));
            json.put("client_secret", properties.get("auth0.client_secret"));
            json.put("redirect_uri", req.getRequestURL().toString());
            json.put("grant_type", "authorization_code");
            json.put("code", authorizationCode);

            JSONResource tokenInfo = resty.json(tokenUri, content(json));
            return new Tokens(tokenInfo.toObject());

        } catch (Exception ex) {
            throw new IllegalStateException("Cannot get Token from Auth0", ex);
        }
    }

    private Auth0User fetchUser(Tokens tokens) {
        Resty resty = createResty();

        String userInfoUri = getUserInfoUri(tokens.getAccessToken());

        try {
            JSONResource json = resty.json(userInfoUri);
            return new Auth0User(json.toObject());
        } catch (Exception ex) {
            throw new IllegalStateException("Cannot get User from Auth0", ex);
        }
    }

    private String getTokenUri() {
        return getUri("/oauth/token");
    }

    private String getUserInfoUri(String accessToken) {
        return getUri("/userinfo?access_token=" + accessToken);
    }

    private String getUri(String path) {
        return String.format("https://%s%s", (String) properties.get("auth0.domain"), path);
    }

    private String getAuthorizationCode(HttpServletRequest req) {
        String code = req.getParameter("code");
        Validate.notNull(code);
        return code;
    }

    /**
     * Override this method to specify a different Resty client. For example, if
     * you want to add a proxy, this would be the place to set it
     *
     * @return {@link Resty} that will be used to perform all requests to Auth0
     */
    protected Resty createResty() {
        return new Resty();
    }

    private boolean isValidRequest(HttpServletRequest req,
                                   HttpServletResponse resp) throws IOException {
        if (hasError(req) || !isValidState(req)) {
            return false;
        }
        return true;
    }

    private boolean isValidState(HttpServletRequest req) {
        final String stateValue = req.getParameter("state");
        Map<String, String> pairs;
        try {
            pairs = Helpers.splitQuery(stateValue);
        } catch (UnsupportedEncodingException e) {
            return false;
        }
        final String externalReturnUrl = pairs.get("eru");
        if (externalReturnUrl != null) {
            req.setAttribute("externalReturnUrl", externalReturnUrl);
        }
        final boolean trusted = externalReturnUrl == null || Helpers.isTrustedExternalReturnUrl(externalReturnUrl);
        final String state = pairs.get("nonce");
        return state != null && state.equals(getNonceStorage(req).getState()) && trusted;
    }

    private static boolean hasError(HttpServletRequest req) {
        return req.getParameter("error") != null;
    }

    static String readParameter(String parameter, ServletConfig config) {
        String first = config.getInitParameter(parameter);
        if (hasValue(first)) {
            return first;
        }
        final String second = config.getServletContext().getInitParameter(
                parameter);
        if (hasValue(second)) {
            return second;
        }
        throw new IllegalArgumentException(parameter + " needs to be defined");
    }

    private static boolean hasValue(String value) {
        return value != null && value.trim().length() > 0;
    }

    /**
     * Override this method to specify a different NonceStorage:
     * <p>
     * <code>
     * protected NonceStorage getNonceStorage(HttpServletRequest request) {
     * return MyNonceStorageImpl(request);
     * }
     * </code>
     */

    protected NonceStorage getNonceStorage(HttpServletRequest request) {
        return new RequestNonceStorage(request);
    }

}
