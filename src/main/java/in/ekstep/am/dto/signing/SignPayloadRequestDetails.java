package in.ekstep.am.dto.signing;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Arrays;

@JsonIgnoreProperties(ignoreUnknown = true)
public class SignPayloadRequestDetails {

  @JsonProperty
  private Payload[] data;

  public Payload[] data() {
    return data;
  }

  private SignPayloadRequestDetails() {
  }

  public SignPayloadRequestDetails(Payload[] data) {
    this.data = data;
  }

  @Override
  public String toString() {
    return "SignChildTokensRequestDetails{" +
            "data=" + Arrays.toString(data) +
            '}';
  }

}
