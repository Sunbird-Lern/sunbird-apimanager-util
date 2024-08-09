package in.ekstep.am.dto.signing;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import in.ekstep.am.dto.ResponseParams;
import in.ekstep.am.dto.ResponseStatus;

@JsonIgnoreProperties(ignoreUnknown = true)
public class SignPayloadResponse {
  @JsonProperty
  private String id;
  @JsonProperty
  private String ver;
  @JsonProperty
  private long ets;
  @JsonProperty
  private ResponseParams params;
  @JsonProperty
  private SignPayloadResult result;

  private SignPayloadResponse() {
  }

  public SignPayloadResponse(String id, String ver, long ets, ResponseParams params, SignPayloadResult result) {
    this.id = "ekstep.api.am.adminutil.sign.payload";
    this.ver = ver;
    this.ets = ets;
    this.params = params;
    this.result = result;
  }

  @Override
  public String toString() {
    return "SignChildTokensResponse{" +
        "id='" + id + '\'' +
        ", ver='" + ver + '\'' +
        ", ets=" + ets +
        ", params=" + params +
        ", result=" + result +
        '}';
  }

  public boolean successful() {
    return params.status() == ResponseStatus.successful;
  }
}
