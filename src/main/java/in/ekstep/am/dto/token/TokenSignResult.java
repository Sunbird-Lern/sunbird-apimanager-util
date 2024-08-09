package in.ekstep.am.dto.token;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
public class TokenSignResult {
    @JsonProperty(value = "access_token")
    private String accessToken;
    @JsonProperty(value = "expires_in")
    private long expiresIn;
    @JsonProperty(value = "refresh_expires_in")
    private long refreshExpiresIn;
    @JsonProperty(value = "refresh_token")
    private String refreshToken;

    private TokenSignResult() {
    }

    public TokenSignResult(String accessToken, long expiresIn, long refreshExpiresIn, String refreshToken) {
        this.accessToken = accessToken;
        this.expiresIn = expiresIn;
        this.refreshExpiresIn = refreshExpiresIn;
        this.refreshToken = refreshToken;
    }

    public TokenSignResult(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    @Override
    public String toString() {
        return "CreateKeycloakRefreshResult{" +
                "accessToken='" + accessToken + '\'' +
                ", expiresIn='" + expiresIn + '\'' +
                ", refresh_expiresIn=" + refreshExpiresIn +
                ", refreshToken=" + refreshToken +
                '}';
    }
}
