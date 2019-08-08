import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPrivateKeySpec;
import javax.crypto.spec.DHPublicKeySpec;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;


public class Utils {

    public static DHParameterSpec generateDhParamenters(int k_len) throws NoSuchAlgorithmException, InvalidParameterSpecException {
        System.out.print("Creating Diffie-Hellman parameters...");
        AlgorithmParameterGenerator dh_param_gen=AlgorithmParameterGenerator.getInstance("DH");
        dh_param_gen.init(k_len);
        DHParameterSpec dh_param_spec=(DHParameterSpec)dh_param_gen.generateParameters().getParameterSpec(DHParameterSpec.class);
        System.out.println(" done.");
        return dh_param_spec;
    }


    public static KeyPair generateDhKeyPair(DHParameterSpec dh_param_spec) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator key_pair_gen=KeyPairGenerator.getInstance("DH");
        key_pair_gen.initialize(dh_param_spec);
        System.out.print("Generating DH keypair...");
        KeyPair key_pair=key_pair_gen.generateKeyPair();
        System.out.println(" done.");
        return key_pair;
    }


    public static KeyPair getDhKeyPair(DHParameterSpec dh_param_spec, BigInteger x) throws NoSuchAlgorithmException, InvalidKeySpecException {
        BigInteger g=dh_param_spec.getG();
        BigInteger p=dh_param_spec.getP();
        BigInteger y=g.modPow(x,p);
        KeyFactory dh_key_factory=KeyFactory.getInstance("DH");
        KeyPair key_pair=new KeyPair(dh_key_factory.generatePublic(new DHPublicKeySpec(y,p,g)),dh_key_factory.generatePrivate(new DHPrivateKeySpec(x,p,g)));
        return key_pair;
    }

    public static byte[] computeDhSecret(KeyPair key_pair, PublicKey y) throws InvalidKeyException, NoSuchAlgorithmException {
        KeyAgreement key_agree=KeyAgreement.getInstance("DH");
        key_agree.init(key_pair.getPrivate());
        key_agree.doPhase(y,true);
        return key_agree.generateSecret();
    }
}
