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

    private final String userId;
    private final String name;
    private final String nickname;
    private final String picture;
    private final String email;
    private final Boolean emailVerified;
    private final String givenName;
    private final String familyName;
    private final Date createdAt;
    private final Map<String, Object> extraInfo;
    private final List<String> roles;
    private final List<String> groups;

    /**
     * User Information
     *
     * @param userInfo the User Information from which to extract the information values
     */
    Auth0User(final UserInfo userInfo) {
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

    /**
     * Getter for the User unique Identifier.
     *
     * @return the user id or null if missing.
     */
    public String getUserId() {
        return userId;
    }

    /**
     * Getter for the name.
     *
     * @return the name or null if missing.
     */
    public String getName() {
        return name;
    }

    /**
     * Getter for the nickname.
     *
     * @return the nickname or null if missing.
     */
    public String getNickname() {
        return nickname;
    }

    /**
     * Getter for the picture url.
     *
     * @return the picture url or null if missing.
     */
    public String getPicture() {
        return picture;
    }

    /**
     * Getter for the email.
     *
     * @return the email or null if missing.
     */
    public String getEmail() {
        return email;
    }

    /**
     * Whether the user's email was verified or not.
     *
     * @return true if the email was verified, false otherwise.
     */
    public boolean isEmailVerified() {
        return emailVerified;
    }

    /**
     * Getter for the given name.
     *
     * @return the given name or null if missing.
     */
    public String getGivenName() {
        return givenName;
    }

    /**
     * Getter for the family name.
     *
     * @return the family name or null if missing.
     */
    public String getFamilyName() {
        return familyName;
    }

    /**
     * Getter for the Date this user was created.
     *
     * @return the Date of creation or null if missing.
     */
    public Date getCreatedAt() {
        return createdAt;
    }

    /**
     * Getter for the values that are not part of the normalized information.
     *
     * @return the extra information.
     */
    public Map<String, Object> getExtraInfo() {
        return Collections.unmodifiableMap(extraInfo);
    }

    /**
     * Getter for the roles this user has.
     *
     * @return the roles of the user or an empty list if missing.
     */
    public List<String> getRoles() {
        return Collections.unmodifiableList(roles);
    }

    /**
     * Getter for the groups this user has.
     *
     * @return the groups of the user or an empty list if missing.
     */
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
