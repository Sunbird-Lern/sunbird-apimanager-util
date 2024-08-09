package in.ekstep.am.dto.signing;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
public class SignPayloadResult {
  @JsonProperty
  private Payload[] data;

  public SignPayloadResult(Payload[] data) {
    this.data = data;
  }

}
