package in.ekstep.am.dto.signing;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;
import java.util.Map;

@JsonIgnoreProperties(ignoreUnknown = true)
public class SignPayloadRequest {
  @JsonProperty
  private String id;

  @JsonProperty
  private String ver;

  @JsonProperty
  private long ets;

  @JsonProperty
  private Map<String, Object> params;

  @JsonProperty
  @Valid
  @NotNull(message = "REQUEST IS MANDATORY")
  private SignPayloadRequestDetails request;

  private SignPayloadRequest() {
  }

  public SignPayloadRequest(Map<String, Object> params, SignPayloadRequestDetails request) {
    this.params = params;
    this.request = request;
  }

  public String msgid() {
    return params == null ? "" : params.get("msgid") == null ? "" : (String) params.get("msgid");
  }

  public SignPayloadRequestDetails getRequest() {
    return request;
  }
}
