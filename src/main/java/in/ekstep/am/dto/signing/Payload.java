package in.ekstep.am.dto.signing;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import in.ekstep.am.constraint.NoSpace;
import org.hibernate.validator.constraints.NotEmpty;

@JsonIgnoreProperties(ignoreUnknown = true)
public class Payload {
    @JsonProperty
    @NotEmpty(message = "parentId IS MANDATORY")
    @NoSpace(message = "parentId MUST NOT HAVE SPACE")
    private String parentId;

    @JsonProperty
    @NotEmpty(message = "childId (sub) IS MANDATORY")
    @NoSpace(message = "childId (sub) MUST NOT HAVE SPACE")
    private String sub;

    @JsonProperty
    private String token;

    private long exp;
    private long iat;

    private Payload() {
    }

    public Payload(String parentId, String sub) {
        this.parentId = parentId;
        this.sub = sub;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public void setExp(long exp) {
        this.exp = exp;
    }

    public void setIat(long iat) {
        this.iat = iat;
    }

    @Override
    public String toString() {
        return "SigningPayload{" +
                "parentId='" + parentId + '\'' +
                ", sub='" + sub + '\'' +
                '}';
    }
}
