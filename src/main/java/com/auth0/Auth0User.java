package com.auth0;

import com.auth0.json.auth.UserInfo;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;

import java.io.Serializable;
import java.text.SimpleDateFormat;
import java.util.*;

/**
 * Auth0 User information.
 */
@SuppressWarnings("unused")
public class Auth0User implements Serializable {

    private static final long serialVersionUID = 2371882820082543721L;

    /**
     * The userId of the user
     */
    private final String userId;

    /**
     * The name assigned to the user
     */
    private final String name;

    /**
     * The nickname assigned to the user
     */
    private final String nickname;

    /**
     * The picture (gravatar) of the user
     */
    private final String picture;

    /**
     * The email assigned to the user
     */
    private final String email;

    /**
     * The email verified or not
     */
    private final Boolean emailVerified;

    /**
     * The given name assigned to the user
     */
    private final String givenName;

    /**
     * The family name assigned to the user
     */
    private final String familyName;

    /**
     * The created at date
     */
    private final Date createdAt;

    /**
     * Extra values of the user that is not part of the normalized information.
     */
    private final Map<String, Object> extraInfo;

    /**
     * The Roles assigned to the user
     */
    private final List<String> roles;

    /**
     * The Groups assigned to the user
     */
    private final List<String> groups;

    /**
     * User Information
     *
     * @param userInfo the User Information from which to extract the information values
     */
    public Auth0User(final UserInfo userInfo) {
        Map<String, Object> info = new HashMap<>(userInfo.getValues());
        this.userId = removeOrNull(info, "sub", String.class);
        this.name = removeOrNull(info, "name", String.class);
        this.nickname = removeOrNull(info, "nickname", String.class);
        this.picture = removeOrNull(info, "picture", String.class);
        this.email = removeOrNull(info, "email", String.class);
        this.emailVerified = removeOrNull(info, "email_verified", Boolean.class);
        this.givenName = removeOrNull(info, "given_name", String.class);
        this.familyName = removeOrNull(info, "family_name", String.class);
        this.createdAt = parseDate(removeOrNull(info, "created_at", String.class));

        this.roles = info.containsKey("roles") ? (List<String>) info.remove("roles") : new ArrayList<String>();
        this.groups = info.containsKey("groups") ? (List<String>) info.remove("groups") : new ArrayList<String>();
        this.extraInfo = info;
    }

    public String getUserId() {
        return userId;
    }

    public String getName() {
        return name;
    }

    public String getNickname() {
        return nickname;
    }

    public String getPicture() {
        return picture;
    }

    public String getEmail() {
        return email;
    }

    public boolean isEmailVerified() {
        return emailVerified;
    }

    public String getGivenName() {
        return givenName;
    }

    public String getFamilyName() {
        return familyName;
    }

    public Date getCreatedAt() {
        return createdAt;
    }

    public Map<String, Object> getExtraInfo() {
        return Collections.unmodifiableMap(extraInfo);
    }

    public List<String> getRoles() {
        return Collections.unmodifiableList(roles);
    }

    public List<String> getGroups() {
        return Collections.unmodifiableList(groups);
    }

    private <T> T removeOrNull(Map<String, Object> values, String key, Class<T> clazz) {
        return values.containsKey(key) ? clazz.cast(values.remove(key)) : null;
    }

    private Date parseDate(String stringDate) {
        if (stringDate == null) {
            return null;
        }

        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
        Date result = null;
        try {
            result = sdf.parse(stringDate);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return result;
    }

    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (obj == this) {
            return true;
        }
        if (obj.getClass() != getClass()) {
            return false;
        }
        final Auth0User rhs = (Auth0User) obj;
        return new EqualsBuilder()
                .appendSuper(super.equals(obj))
                .append(userId, rhs.userId)
                .isEquals();
    }

    public int hashCode() {
        return new HashCodeBuilder(17, 37).
                append(userId).
                toHashCode();
    }

    public String toString() {
        return new ToStringBuilder(this).
                append("userId", userId).
                append("name", name).
                append("email", email).
                toString();
    }

}
