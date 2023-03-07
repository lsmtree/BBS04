
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class SHA {
    public byte[] SHA256_JAVA(String str) {
        MessageDigest messageDigest;
        byte[] res = null;
        try {
            messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(str.getBytes("UTF-8"));
            res = messageDigest.digest();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return res;
    }

    public static String MD5HASH_JAVA(String str) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        //为MD5哈希创建 MessageDigest 实例
        MessageDigest messageDigest = MessageDigest.getInstance("MD5");

        //加盐
//        SecureRandom secureRandom = new SecureRandom();
//        byte[] salt = new byte[16];
//        secureRandom.nextBytes(salt);
//        messageDigest.update(salt);

        //通过str更新messageDigest
        messageDigest.update(str.getBytes("UTF-8"));
        //get hashBytes
        byte[] hashBytes = messageDigest.digest();
        //convert hash bytes to hex format
        StringBuilder builder = new StringBuilder();
        for(byte b: hashBytes) {
            builder.append(String.format("%02x",b));
        }
        return builder.toString();
    }

    public static void main(String[] args) throws UnsupportedEncodingException, NoSuchAlgorithmException {
        String test = "我的";
        String res = MD5HASH_JAVA(test);
        System.out.println(res);
    }
}
//76d80224611fc919a5d54f0ff9fba446
//76d80224611fc919a5d54f0ff9fba446

//07b181184280e1909724fc0d6c2e9b1d
//07b181184280e1909724fc0d6c2e9b1d
//----  加盐对比  ------
//