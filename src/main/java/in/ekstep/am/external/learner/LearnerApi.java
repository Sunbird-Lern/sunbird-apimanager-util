package in.ekstep.am.external.learner;

import in.ekstep.am.external.AmResponse;

public interface LearnerApi {

  AmResponse getUserRolesById(String userId) throws Exception;
}
