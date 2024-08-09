package in.ekstep.am.builder;

import in.ekstep.am.dto.token.TokenResponseParams;
import in.ekstep.am.dto.token.TokenSignResponse;
import in.ekstep.am.dto.token.TokenSignResult;

public class TokenSignResponseBuilder extends ResponseBuilder<TokenSignResponse> implements TokenDetails {

    private String accessToken;
    private long expiresIn;
    private long refreshExpiresIn;
    private String refreshToken;

    public static TokenSignResponseBuilder newInstance() {
        return new TokenSignResponseBuilder();
    }

    public TokenSignResponse build() {
        return new TokenSignResponse("api.refresh.token",
                "1.0", System.currentTimeMillis(), success ? TokenResponseParams.successful() : TokenResponseParams.failed(err, errMsg),
                new TokenSignResult(accessToken, expiresIn, refreshExpiresIn, refreshToken));
    }

    @Override
    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    @Override
    public void setExpiresIn(long expiresIn) {
        this.expiresIn = expiresIn;
    }

    @Override
    public void setRefreshExpiresIn(long refreshExpiresIn) {
        this.refreshExpiresIn = refreshExpiresIn;
    }

    @Override
    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }

}
