package in.ekstep.am.jwt;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import java.io.FileInputStream;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@Component
public class KeyManager {
    private final Logger log = LoggerFactory.getLogger(this.getClass());
    private static final String SEPARATOR = "_";
    private Map<String, KeyData> keyMap = new HashMap<String, KeyData>();
    private Map<String, String> keyMetadata = new HashMap<>();

    @Autowired
    private Environment environment;

    @PostConstruct
    public void init() throws Exception {
        String keys[] = environment.getProperty("am.admin.api.keys").split(",");

        for (String key :keys) {
            loadKeys(key);
        }
        if(environment.getProperty("refresh.token.preload").equals("true")) {
            loadRefreshTokenParams();
        }
    }

    private void loadKeys(String keyName) throws Exception {
        String basePath = environment.getProperty("am.admin.api."+ keyName + ".basepath");
        String keyPrefix = environment.getProperty("am.admin.api."+ keyName + ".keyprefix");
        int keyCount = Integer.parseInt(environment.getProperty("am.admin.api."+ keyName + ".keycount"));
        int keyStart = Integer.parseInt(environment.getProperty("am.admin.api."+ keyName + ".keystart"));
        keyMetadata.put(keyName + SEPARATOR + "keyCount", String.valueOf(keyCount));
        keyMetadata.put(keyName + SEPARATOR + "keyStart", String.valueOf(keyStart));
        keyMetadata.put(keyName + SEPARATOR + "keyPrefix", String.valueOf(keyPrefix));
        keyMetadata.put(keyName + SEPARATOR + "basePath", String.valueOf(basePath));

        for(int i = keyStart; i < (keyStart + keyCount); i++) {
            log.info("Private key loaded - " + basePath + keyPrefix + i);
            String keyId = keyPrefix + i;
                keyMap.put(keyId, new KeyData(keyId, loadPrivateKey(basePath + keyId), null));
        }
    }

    private void loadRefreshTokenParams() throws Exception {
        String basePath = environment.getProperty("refresh.token.public.basepath");
        String keyPrefix = environment.getProperty("refresh.token.public.keyprefix");
        String keyId = environment.getProperty("refresh.token.kid");
        String secretKey = environment.getProperty("refresh.token.secret.key");
        keyMetadata.put("refresh.token.kid", keyId);
        keyMetadata.put("refresh.token.secret.key", secretKey);
        keyMetadata.put("refresh.token.domain", environment.getProperty("refresh.token.domain"));
        keyMetadata.put("access.token.validity", environment.getProperty("access.token.validity"));
        keyMetadata.put("refresh.token.offline.validity", environment.getProperty("refresh.token.offline.validity"));
        keyMetadata.put("refresh.token.log.older.than", environment.getProperty("refresh.token.log.older.than"));
        keyMap.put(keyId, new KeyData(keyId, null, loadPublicKey(basePath + keyPrefix)));
    }

    public KeyData getRandomKey(String keyName) {
        int keyCount = Integer.parseInt(keyMetadata.get(keyName + SEPARATOR + "keyCount"));
        int keyStart = Integer.parseInt(keyMetadata.get(keyName + SEPARATOR + "keyStart"));
        String keyPrefix = keyMetadata.get(keyName + SEPARATOR + "keyPrefix");
        int randomKeyId = (int) (Math.random() * keyCount);
        int keyId = keyStart + randomKeyId;
        return keyMap.get(keyPrefix + keyId);
    }

    private PrivateKey loadPrivateKey(String path) throws Exception {
        FileInputStream in = new FileInputStream(path);
        byte[] keyBytes = new byte[in.available()];
        in.read(keyBytes);
        in.close();

        String privateKey = new String(keyBytes, "UTF-8");
        privateKey = privateKey
                .replaceAll("(-+BEGIN RSA PRIVATE KEY-+\\r?\\n|-+END RSA PRIVATE KEY-+\\r?\\n?)", "")
                .replaceAll("(-+BEGIN PRIVATE KEY-+\\r?\\n|-+END PRIVATE KEY-+\\r?\\n?)", "");

        keyBytes = Base64Util.decode(privateKey.getBytes("UTF-8"), Base64Util.DEFAULT);

        // generate private key
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(spec);
    }

    private PublicKey loadPublicKey(String path) throws Exception {
        FileInputStream in = new FileInputStream(path);
        byte[] keyBytes = new byte[in.available()];
        in.read(keyBytes);
        in.close();

        String publicKey = new String(keyBytes, "UTF-8");
        publicKey = publicKey
                .replaceAll("(-+BEGIN RSA PUBLIC KEY-+\\r?\\n|-+END RSA PUBLIC KEY-+\\r?\\n?)", "")
                .replaceAll("(-+BEGIN PUBLIC KEY-+\\r?\\n|-+END PUBLIC KEY-+\\r?\\n?)", "");
        byte[] publicBytes = Base64.getMimeDecoder().decode(publicKey);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        log.info("Public key loaded - " + path);
        return keyFactory.generatePublic(keySpec);
    }

    public String getValueFromKeyMetaData(String keyId) {
        return keyMetadata.get(keyId);
    }

    public KeyData getValueFromKeyMap(String keyId) {
        return keyMap.get(keyId);
    }
}
