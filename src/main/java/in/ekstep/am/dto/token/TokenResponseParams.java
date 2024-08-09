package in.ekstep.am.dto.token;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.UUID;

@JsonIgnoreProperties(ignoreUnknown = true)
public class TokenResponseParams {
    @JsonProperty
    private String resmsgid;
    @JsonProperty
    private TokenResponseStatus status;
    @JsonProperty
    private String err;
    @JsonProperty
    private String errmsg;

    private TokenResponseParams() {
    }

    public TokenResponseParams(TokenResponseStatus status, String err, String errmsg) {
        this.resmsgid = UUID.randomUUID().toString();
        this.status = status;
        this.err = err;
        this.errmsg = errmsg;
    }

    public static TokenResponseParams successful() {
        return new TokenResponseParams(TokenResponseStatus.successful, null, null);
    }

    public static TokenResponseParams failed(String err, String errmsg) {
        return new TokenResponseParams(TokenResponseStatus.failed, err, errmsg);
    }

    public TokenResponseStatus status() {
        return status;
    }

    @Override
    public String toString() {
        return "ResponseParams{" +
                "resmsgid='" + resmsgid + '\'' +
                ", status=" + status +
                ", err='" + err + '\'' +
                ", errmsg='" + errmsg + '\'' +
                '}';
    }
}