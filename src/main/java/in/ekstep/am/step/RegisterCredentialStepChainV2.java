package in.ekstep.am.step;

import in.ekstep.am.builder.RegisterCredentialResponseBuilder;
import in.ekstep.am.dto.credential.RegisterCredentialRequest;
import in.ekstep.am.external.AmAdminApi;
import in.ekstep.am.jwt.Base64Util;
import in.ekstep.am.jwt.KeyManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import java.io.FileInputStream;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static java.util.Arrays.asList;

@Component
public class RegisterCredentialStepChainV2 {

  @Autowired
  private KeyManager keyManager;

  public void execute(String consumer_name, RegisterCredentialRequest request, RegisterCredentialResponseBuilder responseBuilder) throws Exception {
    for (Step step : stepChain(consumer_name, request, responseBuilder)) {
      if (responseBuilder.successful()) {
        step.execute();
      }
    }
  }

  private List<Step> stepChain(String consumer_name, RegisterCredentialRequest request, RegisterCredentialResponseBuilder responseBuilder) {
    SignCredentialWithKeyStep createCredentialWithKeyStep = new SignCredentialWithKeyStep(
            consumer_name, responseBuilder, request.key(), keyManager);
    return asList(createCredentialWithKeyStep);
  }
}
