package com.auth0;

import static java.util.Arrays.asList;
import static us.monoid.web.Resty.content;
import static us.monoid.web.Resty.form;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Properties;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.lang3.Validate;

import us.monoid.json.JSONObject;
import us.monoid.web.JSONResource;
import us.monoid.web.Resty;

public class Auth0ServletCallback extends HttpServlet {

	private Properties properties = new Properties();
	private String redirectOnSuccess;
	private String redirectOnFail;

	/**
	 * Fetch properties to be used. User is encourage to override this method.
	 * 
	 * Auth0 uses the ServletContext parameters:
	 * 
	 * <dl>
	 * <dt>auth0.client_id</dd>
	 * <dd>Application client id</dd>
	 * <dt>auth0.client_secret</dt>
	 * <dd>Application client secret</dd>
	 * <dt>auth0.domain</dt>
	 * <dd>Auth0 domain</dd>
	 * </dl>
	 * 
	 * Auth0ServletCallback uses these ServletConfig parameters:
	 * 
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
				onSuccess(req, resp);
			} catch (IllegalArgumentException ex) {
				onFailure(req, resp, ex);
			} catch (IllegalStateException ex) {
				onFailure(req, resp, ex);
			}

		}
	}

	protected void onSuccess(HttpServletRequest req, HttpServletResponse resp)
			throws ServletException, IOException {
		// Redirect user to home
		resp.sendRedirect(req.getContextPath() + redirectOnSuccess);
	}

	protected void onFailure(HttpServletRequest req, HttpServletResponse resp,
			Exception ex) throws ServletException, IOException {
		ex.printStackTrace();
		resp.sendRedirect(req.getContextPath() + redirectOnFail + "?"
				+ req.getQueryString());
	}

	protected void store(Tokens tokens, Auth0User user, HttpServletRequest req) {
		HttpSession session = req.getSession(true);

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
		return req.getParameter("state")
				.equals(getNonceStorage(req).getState());
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
	 * 
	 * <code>
	 *     protected NonceStorage getNonceStorage(HttpServletRequest request) {
	 *         return MyNonceStorageImpl(request);
	 *     }
	 * </code>
	 */

	protected NonceStorage getNonceStorage(HttpServletRequest request) {
		return new RequestNonceStorage(request);
	}

}
