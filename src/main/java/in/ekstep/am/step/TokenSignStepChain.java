package in.ekstep.am.step;

import in.ekstep.am.dto.token.TokenSignRequest;
import in.ekstep.am.external.learner.LearnerApi;
import in.ekstep.am.jwt.KeyManager;
import in.ekstep.am.builder.TokenSignResponseBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;
import java.util.List;
import static java.util.Arrays.asList;

@Component
public class TokenSignStepChain {

    private final Logger log = LoggerFactory.getLogger(this.getClass());
    @Autowired
    private KeyManager keyManager;
    @Autowired
    @Qualifier("learner.api.client")
    private LearnerApi learnerApi;
    @Autowired
    private Environment environment;

    public void execute(TokenSignRequest token, TokenSignResponseBuilder tokenSignResponseBuilder) throws Exception {
        for (TokenStep step : stepChain(token, tokenSignResponseBuilder)) {
            if (tokenSignResponseBuilder.successful()) {
                step.execute();
            }
        }
    }

    private List<TokenStep> stepChain(TokenSignRequest token, TokenSignResponseBuilder tokenSignResponseBuilder) {
        TokenSignStep tokenSignStep = new TokenSignStep(token, tokenSignResponseBuilder, keyManager, learnerApi, environment);
        return asList(tokenSignStep);
    }
}