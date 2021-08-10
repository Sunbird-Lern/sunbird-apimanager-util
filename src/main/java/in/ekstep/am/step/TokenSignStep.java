package in.ekstep.am.step;

import in.ekstep.am.dto.token.TokenSignRequest;
import in.ekstep.am.jwt.*;
import in.ekstep.am.builder.TokenSignResponseBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import java.math.BigDecimal;
import java.util.HashMap;
import java.util.Map;

import static java.text.MessageFormat.format;

public class TokenSignStep implements TokenStep {

    private final Logger log = LoggerFactory.getLogger(this.getClass());
    @Autowired
    TokenSignResponseBuilder tokenSignResponseBuilder;
    @Autowired
    private KeyManager keyManager;
    @Autowired
    TokenSignRequest token;
    @Autowired
    private KeyData keyData;

    private String currentToken, kid, iss;
    private Map headerData, bodyData;
    private long accessTokenValidity, refreshTokenValidity, offlineTokenValidity, currentTime, tokenWasIssuedAt;

    public TokenSignStep(TokenSignRequest token, TokenSignResponseBuilder tokenSignResponseBuilder, KeyManager keyManager) {
        this.token = token;
        this.tokenSignResponseBuilder = tokenSignResponseBuilder;
        this.keyManager = keyManager;
    }

    private boolean isJwtTokenValid() {
        currentToken = token.getRefresh_token();

        if(currentToken.split("\\.").length != 3 || currentToken.equals(null)){
            log.error("Invalid length or null, invalidToken: " + currentToken);
            return false;
        }

        headerData = GsonUtil.fromJson(new String(Base64Util.decode(currentToken.split("\\.")[0], 11)), Map.class);
        bodyData = GsonUtil.fromJson(new String(Base64Util.decode(currentToken.split("\\.")[1], 11)), Map.class);

        kid = keyManager.getValueFromKeyMetaData("refresh.token.kid");
        if (!headerData.get("kid").equals(kid) && !headerData.get("alg").equals("HS256")) {
            log.error(format("Invalid kid: {0}, invalidToken: {1}", headerData.get("kid"), currentToken));
            return false;
        }

        if (!headerData.get("alg").equals("RS256") && !headerData.get("alg").equals("HS256")) {
            log.error(format("Invalid algorithm: {0}, invalidToken: {1}", headerData.get("alg"), currentToken));
            return false;
        }

        if (!headerData.get("typ").equals("JWT")) {
            log.error(format("Invalid typ: {0}, invalidToken: {1}", headerData.get("typ"), currentToken));
            return false;
        }

        iss = keyManager.getValueFromKeyMetaData("refresh.token.domain");
        if (!bodyData.get("iss").equals(iss)) {
            log.error(format("Invalid ISS: {0}, invalidToken: {1}",bodyData.get("iss"), currentToken));
            return false;
        }

        if (!bodyData.get("typ").equals("Offline") && !bodyData.get("typ").equals("Refresh")) {
            log.error(format("Not an offline or refresh token: {0}, invalidToken: {1}", bodyData.get("typ"), currentToken));
            return false;
        }

        if(headerData.get("alg").equals("RS256")) {
            if (!JWTUtil.verifyRS256Token(currentToken, keyManager, kid)) {
                log.error(format("Invalid RS256 Signature, invalidToken: {0}", currentToken));
                return false;
            }
        }
        else {
            String secretKey, SEPARATOR = ".";
            String[] tokenSplitData;
            tokenSplitData = currentToken.split("\\.");
            secretKey = keyManager.getValueFromKeyMetaData("refresh.token.secret.key");
            String payload = tokenSplitData[0] + SEPARATOR + tokenSplitData[1];
            String token = JWTUtil.createHS256Token(payload, Base64Util.decode(secretKey, 11));
            if(!token.equals(currentToken)) {
                log.error(format("Invalid HS256 Signature, invalidToken: {0}", currentToken));
                return false;
            }
        }

        accessTokenValidity = Long.parseLong(keyManager.getValueFromKeyMetaData("access.token.validity"));
        refreshTokenValidity = Long.parseLong(keyManager.getValueFromKeyMetaData("refresh.token.validity"));
        currentTime = System.currentTimeMillis() / 1000;

        if (bodyData.get("typ").equals("Offline")) {
            offlineTokenValidity = Long.parseLong(keyManager.getValueFromKeyMetaData("refresh.token.offline.validity"));
            tokenWasIssuedAt = ((Double) bodyData.get("iat")).longValue();
            long tokenValidTill = tokenWasIssuedAt + offlineTokenValidity;

            if (tokenValidTill < currentTime) {
                log.error("Offline token expired on: " + tokenValidTill + ", invalidToken: " + currentToken);
                return false;
            }

            if (tokenWasIssuedAt > currentTime) {
                log.error("Offline token issued at a future date: " + tokenWasIssuedAt + ", invalidToken: " + currentToken);
                return false;
            }
        }
        else {
            BigDecimal expiry = new BigDecimal(bodyData.get("exp").toString());
            long refreshTokenExpiry = expiry.longValueExact();
            if (currentTime > refreshTokenExpiry) {
                log.error("Refresh token expired on: " + refreshTokenExpiry + ", invalidToken: " + currentToken);
                return false;
            }
        }
        return true;
    }

    private void generateNewAccessToken() {
        Map<String, String> header = new HashMap<>();
        Map<String, Object> body = new HashMap<>();
        long exp = currentTime + accessTokenValidity;
        keyData = keyManager.getRandomKey("access");

        header.put("alg", (String) headerData.get("alg"));
        header.put("typ", (String) headerData.get("typ"));
        header.put("kid", keyData.getKeyId());
        body.put("exp", exp);
        body.put("iat", currentTime);
        body.put("iss", iss);
        body.put("aud", bodyData.get("aud"));
        body.put("sub", bodyData.get("sub"));
        body.put("typ", "Bearer");

        tokenSignResponseBuilder.setAccessToken(JWTUtil.createRS256Token(header, body, keyData.getPrivateKey()));
        tokenSignResponseBuilder.setExpiresIn(accessTokenValidity);
    }

    private void generateNewRefreshToken() {
        Map<String, String> header = new HashMap<>();
        Map<String, Object> body = new HashMap<>();
        long exp;
        if (bodyData.get("typ").equals("Offline")) {
            exp = 0;
        }
        else {
            exp = currentTime + refreshTokenValidity;
        }

        header.put("alg", (String) headerData.get("alg"));
        header.put("typ", (String) headerData.get("typ"));
        header.put("kid", keyData.getKeyId());
        body.put("exp", exp);
        body.put("iat", currentTime);
        body.put("iss", iss);
        body.put("aud", bodyData.get("aud"));
        body.put("sub", bodyData.get("sub"));
        if (bodyData.get("typ").equals("Offline")) {
            body.put("typ", "Offline");
        }
        else {
            body.put("typ", "Refresh");
        }

        tokenSignResponseBuilder.setRefreshToken(JWTUtil.createRS256Token(header, body, keyData.getPrivateKey()));
        tokenSignResponseBuilder.setRefreshExpiresIn(refreshTokenValidity);

        if (bodyData.get("typ").equals("Offline")) {
            long refreshTokenLogOlderThan = Long.parseLong(keyManager.getValueFromKeyMetaData("refresh.token.log.older.than"));
            long diffInDays = (currentTime - tokenWasIssuedAt) / (60 * 60 * 24);
            if (diffInDays >= refreshTokenLogOlderThan)
                log.info("Token issued before: " + diffInDays + ", UID: " + body.get("sub") + ", aud: " + body.get("aud") + ", exp: " + body.get("exp") + ", iat: " + body.get("iat"));
            else
                log.info("Token issued for UID: " + body.get("sub") + ", aud: " + body.get("aud") + ", exp: " + body.get("exp") + ", iat: " + body.get("iat"));
        }
    }

    @Override
    public void execute() {
        if(isJwtTokenValid()) {
            generateNewAccessToken();
            generateNewRefreshToken();
        }
        else
            tokenSignResponseBuilder.markFailure("invalid_grant", "invalid_grant");
    }
}