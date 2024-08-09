package in.ekstep.am.step;

import in.ekstep.am.builder.TokenSignResponseBuilder;
import in.ekstep.am.dto.token.TokenSignRequest;
import in.ekstep.am.external.AmResponse;
import in.ekstep.am.external.learner.LearnerApi;
import in.ekstep.am.jwt.Base64Util;
import in.ekstep.am.jwt.GsonUtil;
import in.ekstep.am.jwt.JWTUtil;
import in.ekstep.am.jwt.KeyData;
import in.ekstep.am.jwt.KeyManager;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.collections4.MapUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.util.StringUtils;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

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
  @Autowired
  private LearnerApi learnerApi;
  @Autowired
  private Environment environment;

  private String currentToken, kid, iss;
  private Map headerData, bodyData;
  private long offlineTokenValidity, currentTime, tokenWasIssuedAt, tokenValidTill, tokenExpiry;

  public TokenSignStep(TokenSignRequest token, TokenSignResponseBuilder tokenSignResponseBuilder, KeyManager keyManager, LearnerApi learnerApi, Environment environment) {
    this.token = token;
    this.tokenSignResponseBuilder = tokenSignResponseBuilder;
    this.keyManager = keyManager;
    this.learnerApi = learnerApi;
    this.environment = environment;
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
      log.error(format("Not an Offline or Refresh token: {0}, invalidToken: {1}", bodyData.get("typ"), currentToken));
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

    currentTime = System.currentTimeMillis() / 1000;
    BigDecimal iat = new BigDecimal(bodyData.get("iat").toString());
    BigDecimal exp = new BigDecimal(bodyData.get("exp").toString());
    tokenWasIssuedAt = iat.longValueExact();
    tokenExpiry = exp.longValueExact();

    if(bodyData.get("typ").equals("Offline")) {
      offlineTokenValidity = Long.parseLong(keyManager.getValueFromKeyMetaData("refresh.token.offline.validity"));
      tokenValidTill = tokenWasIssuedAt + offlineTokenValidity;

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
      if(currentTime > tokenExpiry){
        log.error("Refresh token expired on: " + tokenExpiry + ", invalidToken: " + currentToken);
        return false;
      }
    }
    return true;
  }

  private void generateNewJwtToken() {
    Map<String, String> header = new HashMap<>();
    Map<String, Object> body = new HashMap<>();
    keyData = keyManager.getRandomKey("access");
    long tokenValidity = Long.parseLong(keyManager.getValueFromKeyMetaData("access.token.validity"));
    long exp;

    if(bodyData.get("typ").equals("Offline")) {
      if(tokenValidTill > (currentTime + tokenValidity)) {
        exp = currentTime + tokenValidity;
      }
      else {
        exp = tokenValidTill;
      }
    }
    else {
      if(tokenExpiry > (currentTime + tokenValidity)) {
        exp = currentTime + tokenValidity;
      }
      else {
        exp = tokenExpiry;
      }
    }

    header.put("alg", (String) headerData.get("alg"));
    header.put("typ", (String) headerData.get("typ"));
    header.put("kid", keyData.getKeyId());
    body.put("exp", exp);
    body.put("iat", currentTime);
    body.put("iss", iss);
    body.put("aud", bodyData.get("aud"));
    body.put("sub", bodyData.get("sub"));
    body.put("typ", "Bearer");
    body.put("roles",appendDefaultRoles());
    if (Boolean.parseBoolean(environment.getProperty("embed.role"))) {
      try {
        AmResponse response = learnerApi.getUserRolesById(getLmsUserId((String) bodyData.get("sub")));
        if (200 == response.code()) {
          Map<String, Object> learnerResponse = GsonUtil.fromJson(response.body(), Map.class);
          List<Map<String,Object>> roles = appendRoles(learnerResponse);
          body.put("roles", roles);
          if (roles.size() > 1) {
            String name = getUserName(learnerResponse);
            body.put("name", name);
          }
        } else {
          log.info("Got error response from learner api : "+response.body());
        }
      } catch (Exception ex) {
        log.error(format("Exception occurred while fetching user roles for id {0}", bodyData.get("sub")));
      }
    }

    tokenSignResponseBuilder.setAccessToken(JWTUtil.createRS256Token(header, body, keyData.getPrivateKey()));
    tokenSignResponseBuilder.setRefreshToken(currentToken);
    tokenSignResponseBuilder.setExpiresIn(exp - currentTime);

    if(bodyData.get("typ").equals("Offline")) {
      tokenSignResponseBuilder.setRefreshExpiresIn(0);
    }
    else {
      tokenSignResponseBuilder.setRefreshExpiresIn(tokenExpiry - currentTime);
    }

    if(bodyData.get("typ").equals("Offline")) {
      long refreshTokenLogOlderThan = Long.parseLong(keyManager.getValueFromKeyMetaData("refresh.token.log.older.than"));
      long diffInDays = (currentTime - tokenWasIssuedAt) / (60 * 60 * 24);
      if (diffInDays >= refreshTokenLogOlderThan) {
        log.info("Token issued before: " + diffInDays + ", UID: " + body.get("sub") + ", aud: " + body.get("aud") + ", exp: " + body.get("exp") + ", iat: " + body.get("iat"));
      }
      else {
        log.info("Token issued for UID: " + body.get("sub") + ", aud: " + body.get("aud") + ", exp: " + body.get("exp") + ", iat: " + body.get("iat"));
      }
    }
    else {
      log.info("Token issued for UID: " + body.get("sub") + ", aud: " + body.get("aud") + ", exp: " + body.get("exp") + ", iat: " + body.get("iat"));
    }
  }

  private String getUserName(Map<String, Object> learnerResponse) {
    if (MapUtils.isNotEmpty(learnerResponse)) {
      Map<String,Object> result = (Map<String, Object>) learnerResponse.get("result");
      if (MapUtils.isNotEmpty(result)) {
        return (String)result.get("name");
      }
    }
    return "";
  }

  private List<Map<String,Object>> appendRoles(Map<String, Object> learnerResponse) {
    if (MapUtils.isNotEmpty(learnerResponse)) {
      Map<String,Object> result = (Map<String, Object>) learnerResponse.get("result");
      if (MapUtils.isNotEmpty(result)) {
        List roles =  (List<Map<String,Object>>)result.get("roles");
        if (CollectionUtils.isNotEmpty(roles)) {
          checkAndAppendPublicRole(roles);
          return roles;
        }
      }
    }
    return appendDefaultRoles();
  }

  private void checkAndAppendPublicRole(List<Map<String,Object>> roles) {
    // If user doesn't have PUBLIC role.
    Set<String> roleList = new HashSet<>();
    roles.stream().forEach(map -> roleList.add(((String)map.get("role")).toLowerCase()));
    if (!roleList.contains("public")) {
      roles.addAll(appendDefaultRoles());
    }
  }

  private List<Map<String, Object>> appendDefaultRoles() {
    //if user role empty , pass PUBLIC Role
    List<Map<String,Object>> roles = new ArrayList<>();
    Map<String,Object> role = new HashMap<>();
    role.put("role","PUBLIC");
    role.put("scope",new ArrayList<>());
    roles.add(role);
    return roles;
  }

  private String getLmsUserId(String fedUserId) {
    if (!StringUtils.isEmpty(fedUserId) && fedUserId.startsWith("f:")) {
      return fedUserId.substring(fedUserId.lastIndexOf(":")+1);
    }
    return fedUserId;
  }

  @Override
  public void execute() {
    if(isJwtTokenValid())
      generateNewJwtToken();
    else
      tokenSignResponseBuilder.markFailure("invalid_grant", "invalid_grant");
  }
}