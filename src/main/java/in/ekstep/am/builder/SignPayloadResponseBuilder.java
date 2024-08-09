package in.ekstep.am.builder;

import in.ekstep.am.dto.ResponseParams;
import in.ekstep.am.dto.signing.Payload;
import in.ekstep.am.dto.signing.SignPayloadResponse;
import in.ekstep.am.dto.signing.SignPayloadResult;

public class SignPayloadResponseBuilder extends ResponseBuilder<SignPayloadResponse> {

  private String msgid;
  private Payload[] data;

  public static SignPayloadResponseBuilder newInstance() {
    return new SignPayloadResponseBuilder();
  }

  public SignPayloadResponse build() {

    return new SignPayloadResponse(
        "ekstep.api.am.adminutil.sign.payload",
        "1.0",
        System.currentTimeMillis(),
        success ? ResponseParams.successful(this.msgid) : ResponseParams.failed(this.msgid, err, errMsg),
        new SignPayloadResult(data));
  }

  public SignPayloadResponseBuilder withMsgid(String msgid) {
    this.msgid = msgid;
    return this;
  }

  public void setData(Payload[] data) {
    this.data = data;
  }
}
