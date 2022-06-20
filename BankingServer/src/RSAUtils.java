import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Utilities for RSA encryption
 */
public class RSAUtils
{

    public static String saveKey(PublicKey key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    public static PublicKey loadKey(String data) {
        try
        {
            byte[] bytes = Base64.getDecoder().decode(data);
            KeyFactory factory = KeyFactory.getInstance("RSA");
            EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(bytes);
            return factory.generatePublic(publicKeySpec);

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static String encode(PublicKey key, String data) {
        try
        {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] bytes = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(bytes);

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static String decode(PrivateKey key, String data) {
        try
        {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] bytes = cipher.doFinal(Base64.getDecoder().decode(data));
            return new String(bytes);

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

}
