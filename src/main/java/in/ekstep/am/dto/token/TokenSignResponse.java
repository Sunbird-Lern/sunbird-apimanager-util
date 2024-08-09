package in.ekstep.am.dto.token;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
public class TokenSignResponse {
    @JsonProperty
    private String id;
    @JsonProperty
    private String ver;
    @JsonProperty
    private long ts;
    @JsonProperty
    private TokenResponseParams params;
    @JsonProperty
    private TokenSignResult result;

    private TokenSignResponse(){}

    public TokenSignResponse(String id, String ver, long ts, TokenResponseParams params, TokenSignResult result) {
        this.id = id;
        this.ver = ver;
        this.ts = ts;
        this.params = params;
        this.result = result;
    }

    @Override
    public String toString() {
        return "CreateKeycloakRefreshResponse{" +
                "id='" + id + '\'' +
                ", ver='" + ver + '\'' +
                ", ts=" + ts +
                ", params=" + params +
                ", result=" + result +
                '}';
    }

    public boolean successful() {
        return params.status() == TokenResponseStatus.successful;
    }
}
