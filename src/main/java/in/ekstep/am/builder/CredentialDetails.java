package in.ekstep.am.builder;

public interface CredentialDetails {
  void setKey(String key);

  void setSecret(String secret);

  void setToken(String token);

  void markFailure(String error, String errmsg);

  void markSuccess();
}