package in.ekstep.am.jwt;

import java.security.PrivateKey;
import java.util.HashMap;
import java.util.Map;

public class JWTUtil {

    private static String SEPARATOR = ".";

    public static String createHS256Token(String key, String secretKey, Map<String, String> headerOptions) {
        JWTokenType tokenType = JWTokenType.HS256;
        String payLoad = createHeader(tokenType, headerOptions) + SEPARATOR + createClaims(key);
        String signature = encodeToBase64Uri(CryptoUtil.generateHMAC(payLoad, secretKey, tokenType.getAlgorithmName()));
        return payLoad + SEPARATOR + signature;
    }

    public static String createHS256Token(String payLoad, byte[] secretKey) {
        JWTokenType tokenType = JWTokenType.HS256;
        String signature = encodeToBase64Uri(CryptoUtil.generateHMAC(payLoad, secretKey, tokenType.getAlgorithmName()));
        return payLoad + SEPARATOR + signature;
    }

    public static String createRS256Token(String key, PrivateKey privateKey, Map<String, String> headerOptions) {
        JWTokenType tokenType = JWTokenType.RS256;
        String payLoad = createHeader(tokenType, headerOptions) + SEPARATOR + createClaims(key);
        String signature = encodeToBase64Uri(CryptoUtil.generateRSASign(payLoad, privateKey, tokenType.getAlgorithmName()));
        return payLoad + SEPARATOR + signature;
    }

    public static String createRS256Token(Map<String, String> headerOptions, Object payload, PrivateKey privateKey) {
        JWTokenType tokenType = JWTokenType.RS256;
        String payLoad = createHeader(tokenType, headerOptions) + SEPARATOR + createPayload(payload);
        String signature = encodeToBase64Uri(CryptoUtil.generateRSASign(payLoad, privateKey, tokenType.getAlgorithmName()));
        return payLoad + SEPARATOR + signature;
    }

    private static String createHeader(JWTokenType tokenType, Map<String, String> headerOptions) {
        Map<String, String> headerData = new HashMap<>();
        if (headerOptions != null)
            headerData.putAll(headerOptions);
        headerData.put("alg", tokenType.getTokenType());
        return encodeToBase64Uri(GsonUtil.toJson(headerData).getBytes());
    }

    private static String createClaims(String subject) {
        Map<String, Object> payloadData = new HashMap<>();
        payloadData.put("iss", subject);
        payloadData.put("iat", System.currentTimeMillis()/1000);
        return encodeToBase64Uri(GsonUtil.toJson(payloadData).getBytes());
    }

    private static String createPayload(Object payload) {
        return encodeToBase64Uri(GsonUtil.toJson(payload).getBytes());
    }

    private static String encodeToBase64Uri(byte[] data) {
        return Base64Util.encodeToString(data, 11);
    }

    public static boolean verifyRS256Token(String token, KeyManager keyManager, String keyId) {
        String[] tokenElements = token.split("\\.");
        String header = tokenElements[0];
        String body = tokenElements[1];
        String signature = tokenElements[2];
        String payLoad = header + SEPARATOR + body;
        KeyData keyData;
        boolean isValid = false;
        keyData = keyManager.getValueFromKeyMap(keyId);
        if(keyData != null) {
            isValid = CryptoUtil.verifyRSASign(payLoad, decodeFromBase64(signature), keyData.getPublicKey(), "SHA256withRSA");
        }
        return isValid;
    }

    public static Map decodeToken(String token){
        Map<Object, Object> payloadData = GsonUtil.fromJson(new String(decodeFromBase64(token)), Map.class);
        return decodeToken(token);
    }

    public static byte[] decodeFromBase64(String data) {
        return Base64Util.decode(data, 11);
    }
}
