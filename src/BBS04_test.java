import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.io.UnsupportedEncodingException;
import java.util.Base64;
//import it.unisa.dia.gas.plaf.jpbc.util.io.Base64;

public class BBS04_test {

    public static void main(String[] args) throws UnsupportedEncodingException {
        Pairing pair = PairingFactory.getPairing("a.properties");
        BBS04 bbs04 = new BBS04();
        SHA sha256 = new SHA();
        //generate g1 and g2
        Element g1 = pair.getG1().newRandomElement();
        Element g2 = pair.getG2().newRandomElement();

        //generate Group
        BBS04.PrivateKey priv = bbs04.GenerateGroup(g1,g2,pair);

        BBS04.Cert c1 = bbs04.Cert(priv);
        System.out.println("m1.A is :"+c1.A);
        System.out.println("m1.a is :"+c1.a);

        BBS04.Cert c2 = bbs04.Cert(priv);
        System.out.println("m2.A is :"+c2.A);
        //验证群用户有效性
        bbs04.Verify_Cert(c1);
        bbs04.Verify_Cert(c2);
        //进行签名操作
        String msg = "hello world!";
        long sig_start_t1 = System.currentTimeMillis();
        BBS04.Sig sig1 = bbs04.sign(c1,msg);
        long sig_end_t1 = System.currentTimeMillis();
        System.out.println("------签名耗时:"+(sig_end_t1-sig_start_t1)+" ms------");
        BBS04.Sig sig2 = bbs04.sign(c2,"hello");
        System.out.println("签名："+sig1.toString()+"");
        System.out.println("签名所占字节数1："+sig1.toString().getBytes().length);
        System.out.println("签名所占字节数2："+sig2.toString().getBytes().length);
        //验证签名有效性
        long ver_start_t1 = System.currentTimeMillis();
        bbs04.Verify_Sign(sig1, priv.Group);
        long ver_end_t1 = System.currentTimeMillis();
        System.out.println("------验证耗时:"+(ver_end_t1-ver_start_t1)+" ms------");
        bbs04.Verify_Sign(sig2, priv.Group);



        Base64.Encoder encoder = Base64.getEncoder();
        String str ="hhh";
        str = encoder.encodeToString(sig1.t1.toBytes());
        System.out.println("编码："+str);
        Base64.Decoder decoder = Base64.getDecoder();
        byte[] decodeByte =decoder.decode(str);
        sig1.t1.setFromBytes(decodeByte);

        //追踪该签名的群成员
        long open_start_t = System.currentTimeMillis();
        Element open = bbs04.Open(priv,sig1);
        long open_end_t = System.currentTimeMillis();
        System.out.println("------追踪耗时:"+(open_end_t-open_start_t)+" ms------");
        System.out.println("open:"+open.toString());
        System.out.println("c1对比:"+open.equals(c1.A));
        System.out.println("c2对比:"+open.equals(c2.A));





    }

}
