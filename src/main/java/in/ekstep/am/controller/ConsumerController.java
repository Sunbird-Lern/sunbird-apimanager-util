package in.ekstep.am.controller;

import com.codahale.metrics.annotation.Timed;
import in.ekstep.am.builder.RegisterCredentialResponseBuilder;
import in.ekstep.am.dto.credential.RegisterCredentialRequest;
import in.ekstep.am.dto.credential.RegisterCredentialResponse;
import in.ekstep.am.step.RegisterCredentialStepChain;
import in.ekstep.am.step.RegisterCredentialStepChainV2;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

import static java.text.MessageFormat.format;

@RestController
public class ConsumerController {

  private final Logger log = LoggerFactory.getLogger(this.getClass());

  @Autowired
  private RegisterCredentialStepChain registerCredentialStepChain;

  @Autowired
  private RegisterCredentialStepChainV2 registerCredentialStepChainV2;

  @Timed(name = "register-credential-api")
  @RequestMapping(method = RequestMethod.POST, value = "/v1/consumer/{consumer_name}/credential/register",
          consumes = "application/json", produces = "application/json")
  public ResponseEntity<RegisterCredentialResponse> registerCredential(@Valid @PathVariable(value = "consumer_name") String userName, @Valid @RequestBody RegisterCredentialRequest request, BindingResult bindingResult) {

    RegisterCredentialResponseBuilder responseBuilder = new RegisterCredentialResponseBuilder();
    try {
      log.debug(format("GOT REQUEST TO REGISTER CREDENTIAL. REQUEST: {0}, USERNAME:{1}", request, userName));

      if (bindingResult.hasErrors()) {
        return responseBuilder.badRequest(bindingResult);
      }

      responseBuilder
              .withMsgid(request.msgid())
              .withUsername(userName)
              .markSuccess();

      registerCredentialStepChain.execute(userName, request, responseBuilder);
      return responseBuilder.response();
    } catch (Exception e) {
      log.error(format("ERROR WHEN REGISTERING CREDENTIAL. REQUEST: {0}, USERNAME:{1}", request, userName), e);
      return responseBuilder
              .errorResponse("INTERNAL_ERROR", "UNABLE TO REGISTER CREDENTIAL DUE TO INTERNAL ERROR");
    }
  }

  @Timed(name = "register-credential-apiv2")
  @RequestMapping(method = RequestMethod.POST, value = "/v2/consumer/{consumer_name}/credential/register",
          consumes = "application/json", produces = "application/json")
  public ResponseEntity<RegisterCredentialResponse> registerCredentialv2(@Valid @PathVariable(value = "consumer_name") String consumer_name, @Valid @RequestBody RegisterCredentialRequest request, BindingResult bindingResult) {

    RegisterCredentialResponseBuilder responseBuilder = new RegisterCredentialResponseBuilder();
    try {
      if (bindingResult.hasErrors()) {
        return responseBuilder.badRequest(bindingResult);
      }

      responseBuilder
              .withMsgid(request.msgid())
              .withUsername(consumer_name)
              .markSuccess();

      registerCredentialStepChainV2.execute(consumer_name, request, responseBuilder);
      return responseBuilder.response();
    } catch (Exception e) {
      log.error(format("ERROR WHEN REGISTERING CREDENTIAL. REQUEST: {0}, USERNAME:{1}", request, consumer_name), e);
      return responseBuilder
              .errorResponse("INTERNAL_ERROR", "UNABLE TO REGISTER CREDENTIAL DUE TO INTERNAL ERROR");
    }
  }

  @InitBinder
  public void initBinder(WebDataBinder binder) {
    binder.initDirectFieldAccess();
  }
}
