package in.ekstep.am.external;

import okhttp3.Response;

public interface AmAdminApi {
  Integer CREATED = 201;
  Integer DELETED = 204;
  Integer BAD_REQUEST = 400;
  Integer OK = 200;
  Integer CONFLICT = 409;
  Integer NOT_FOUND = 404;

  Response determineHealth() throws Exception;

  AmResponse createCredential(String username, String key) throws Exception;

  AmResponse getCredential(String username, String key) throws Exception;

}
