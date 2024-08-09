package in.ekstep.am.external.learner;

import in.ekstep.am.external.AmResponse;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;

import java.util.Map;
import java.util.Optional;

import static java.text.MessageFormat.format;

public class LearnerApiClient implements LearnerApi {

  @Autowired
  @Qualifier("am.admin.api.client")
  private OkHttpClient okHttpClient;

  @Autowired
  @Qualifier("learner.base.api.url")
  private String learnerApiBaseUrl;

  @Autowired
  @Qualifier("learner.api.auth.key")
  private String learnerApiBearerKey;


  @Override
  public AmResponse getUserRolesById(String userId) throws Exception {
    Request request = new Request.Builder()
      .url(format( learnerApiBaseUrl+"/user/v1/role/read/{0}", userId))
      .method("GET", null)
      .addHeader("Connection","keep-alive")
      .addHeader("Accept", "application/json")
      .addHeader("Content-Type", "application/json")
      .addHeader("Authorization","Bearer "+learnerApiBearerKey)
      .build();
    return executeRequest(request);
  }

  private AmResponse executeRequest(Request request) throws Exception {
    Response response = null;
    try {
      response = okHttpClient
        .newCall(request).execute();
      return new AmResponse(response.code(), response.body().string());
    } finally {
      //Response body must be closed for all requests
      Optional.ofNullable(response).ifPresent((res) -> res.body().close());
    }
  }

}
