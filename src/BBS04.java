// 导入jpbc包
import com.sun.org.apache.xml.internal.security.algorithms.implementations.SignatureDSA;
import it.unisa.dia.gas.jpbc.*;
//import it.unisa.dia.gas.plaf.*;

// BBS04算法的Java实现

public class BBS04 {

    // 群公钥 gpk
    class Group {
        private Element g1;
        private Element h;
        private Element u;
        private Element v;
        private Element g2;
        private Element w;
        private Element ehw;
        private Element ehg2;
        private Element minusEg1g2;
        private Pairing pairing;
    }
    // 群管理员私钥 gmsk
    class PrivateKey {
        Group Group; //群公钥
        private Element xi1;
        private Element xi2;
        private Element gamma;
    }
    // 群成员的私钥 gsk[i]={Ai,ai}
    class Cert {
        Group Group; //群公钥
        Element A;
        Element a;
    }
    // 签名
    static class Sig {
        String m; //待加密的消息，或称为待签名的消息
        Element t1;
        Element t2;
        Element t3;
        Element c;
        Element salpha;
        Element sbeta;
        Element sa;
        Element sdelta1;
        Element sdelta2;

        @Override
        public String toString() {
            return "Sig{" +
                    "m='" + m + '\'' +
                    ", t1=" + t1 +
                    ", t2=" + t2 +
                    ", t3=" + t3 +
                    ", c=" + c +
                    ", salpha=" + salpha +
                    ", sbeta=" + sbeta +
                    ", sa=" + sa +
                    ", sdelta1=" + sdelta1 +
                    ", sdelta2=" + sdelta2 +
                    '}';
        }
    }

    /*
    * @parms g1,g2,pairing
    * @return gmsk
    * 生成群
    * */
    public PrivateKey GenerateGroup(Element g_1,Element g_2, Pairing pairing_) {
        PrivateKey priv = new PrivateKey();
        priv.Group = new Group();
        priv.Group.pairing = pairing_;
        priv.Group.g1 = g_1.getImmutable();
        priv.Group.h = priv.Group.pairing.getG1().newRandomElement().getImmutable();
        priv.Group.g2 = g_2.getImmutable();
        priv.xi1 = priv.Group.pairing.getZr().newRandomElement().getImmutable();
        priv.xi2 = priv.Group.pairing.getZr().newRandomElement().getImmutable();
        Element temp1 = priv.xi1.duplicate().invert();
        Element temp2 = priv.xi2.duplicate().invert();
        priv.Group.u = priv.Group.h.duplicate().powZn(temp1);
        priv.Group.v = priv.Group.h.duplicate().powZn(temp2);
        priv.gamma = priv.Group.pairing.getZr().newRandomElement().getImmutable();
        priv.Group.w =  priv.Group.g2.duplicate().powZn(priv.gamma);
        precompute(priv.Group);
        return priv;
    }


    public void precompute(Group g) {
        g.ehw = g.pairing.pairing(g.h, g.w).getImmutable();
        g.ehg2 = g.pairing.pairing(g.h, g.g2).getImmutable();
        Element t = g.pairing.pairing(g.g1, g.g2).getImmutable(); //取两数的线性配对
        g.minusEg1g2 = t.duplicate().negate().getImmutable(); //取负数
    }

    /*
    * @parms gmsk
    * @return Cert
    * 生成群成员的私钥，即注册群成员
    * */
    public Cert Cert(PrivateKey priv) {
        Cert cert = new Cert();
        cert.Group = priv.Group;
        cert.a = priv.Group.pairing.getZr().newRandomElement().getImmutable();
        Element temp3 = priv.gamma.duplicate().add(cert.a);
        Element temp4 = temp3.duplicate().invert();
        cert.A = priv.Group.g1.duplicate().powZn(temp4);
        return cert;
    }

    /*
    * @parms Cert
    * @return boolean
    * 验证群成员
    * */
    public boolean Verify_Cert(Cert cert) {
        Element temp1 = cert.Group.g2.duplicate().powZn(cert.a);
        Element temp2 = cert.Group.w.duplicate().mul(temp1);
        Element e1 = cert.Group.pairing.pairing(cert.A, temp2).getImmutable();
        Element ttt2 = cert.Group.pairing.pairing(cert.Group.g1, cert.Group.g2).getImmutable();
        if (e1.equals(ttt2)) {
            System.out.println("该群成员私钥有效");
            return true;
        } else {
            System.out.println("该群成员私钥无效");
            return false;
        }
    }

    /*
    * @parms Cert,m(待加密的消息，无较大意义)
    * @retuen Sign
    * 群成员签名
    * */
    public Sig sign(Cert cert, String m) {
        Sig sig = new Sig();
        Element alpha = cert.Group.pairing.getZr().newRandomElement().getImmutable();
        Element beta = cert.Group.pairing.getZr().newRandomElement().getImmutable();
        Element t1 = cert.Group.u.duplicate().powZn(alpha);
        Element t2 = cert.Group.v.duplicate().powZn(beta);
        Element tmp = alpha.duplicate().add(beta);
        Element tmp1 = cert.Group.h.duplicate().powZn(tmp);
        Element t3 = cert.A.duplicate().mul(tmp1).getImmutable();
        Element delta1 = cert.a.duplicate().mul(alpha);
        Element delta2 = cert.a.duplicate().mul(beta);
        Element ralpha = cert.Group.pairing.getZr().newRandomElement().getImmutable();
        Element rbeta = cert.Group.pairing.getZr().newRandomElement().getImmutable();
        //rx := cert.pairing.NewZr().Rand()
        Element rdelta1 = cert.Group.pairing.getZr().newRandomElement().getImmutable();
        Element rdelta2 = cert.Group.pairing.getZr().newRandomElement().getImmutable();
        Element ra = cert.Group.pairing.getZr().newRandomElement().getImmutable();
        Element r1 = cert.Group.u.duplicate().powZn(ralpha);
        Element r2 = cert.Group.v.duplicate().powZn(rbeta);
        //**********************************************************//
        Element temp1 = cert.Group.pairing.pairing(t3,cert.Group.g2).getImmutable();
        Element r3_e1 = temp1.duplicate().powZn(ra);
        Element uuu = ralpha.duplicate().negate();
        Element www = rbeta.duplicate().negate();
        Element xxx = uuu.duplicate().add(www);
        Element r3_e2 = cert.Group.ehw.duplicate().powZn(xxx);
        Element uuu1= rdelta1.duplicate().negate();
        Element www1 = rdelta2.duplicate().negate();
        Element xxx1 = uuu1.duplicate().add(www1);
        Element r3_e3 = cert.Group.ehg2.duplicate().powZn(xxx1);

        //eh3g2:=cert.pairing.NewGT().Pair(cert.h_,cert.g2)
        //r3_e4:=cert.pairing.NewGT().PowZn(eh3g2,rx)
        Element r3 = (r3_e1.duplicate().mul(r3_e2)).duplicate().mul(r3_e3);

        Element tt_temp2 = t1.duplicate().powZn(ra);
        Element tt_temp = rdelta1.duplicate().negate();
        Element tt = cert.Group.u.duplicate().powZn(tt_temp);
        Element r4 = tt.duplicate().mul(tt_temp2);
        Element rr_temp2 = t2.duplicate().powZn(ra);
        Element rr_temp = rdelta2.duplicate().negate();
        Element rr = cert.Group.v.duplicate().powZn(rr_temp);
        Element r5 = rr.duplicate().mul(rr_temp2);
        String s = "";
        s += t1.toString();
        s += t2.toString();
        s += t3.toString();
        s += r1.toString();
        s += r2.toString();
        s += r3.toString();
        s += r4.toString();
        s += r5.toString();
        s += m;

        //计算C
        SHA sha256 = new SHA();
        Element c = cert.Group.pairing.getZr().newElementFromBytes(sha256.SHA256_JAVA(s)).getImmutable();
        //Element c = cert.Group.pairing.getZr().newElement().setFromHash(sha256.SHA256_JAVA(s),0,sha256.SHA256_JAVA(s).length).getImmutable();

        sig.m = m;
        sig.c = c;
        sig.t1 = t1;
        sig.t2 = t2;
        sig.t3 = t3;
        sig.salpha =ralpha.duplicate().add(c.duplicate().mul(alpha));
        sig.sbeta = rbeta.duplicate().add(c.duplicate().mul(beta));
        sig.sa = ra.duplicate().add(c.duplicate().mul(cert.a));
        //sig.sx=cert.pairing.NewZr().Add(rx,cert.pairing.NewZr().Mul(c,cert.x_))
        sig.sdelta1 = rdelta1.duplicate().add(c.duplicate().mul(delta1));
        sig.sdelta2 = rdelta2.duplicate().add(c.duplicate().mul(delta2));
        return sig;
    }

    /*
    * @parms Sig
    * @return boolean
    * 验证签名
    * */
    public boolean Verify_Sign(Sig sig, Group g) {

        //r1 = (g.u^sig.salpha)*(sig.t1^(-c))
        //r2 = (g.v^sig.sbeta)*(sig.t2^(-c))
        Element r1 = (g.u.duplicate().powZn(sig.salpha)).duplicate().mul(sig.t1.duplicate().powZn(sig.c.duplicate().negate())).getImmutable();
        Element r2 = (g.v.duplicate().powZn(sig.sbeta)).duplicate().mul(sig.t2.duplicate().powZn(sig.c.duplicate().negate())).getImmutable();
        //******************************************
        Element temp1  = g.pairing.pairing(sig.t3, g.g2).getImmutable();
        Element r3_e1 = temp1.duplicate().powZn(sig.sa);
        Element uuu = sig.salpha.duplicate().negate();
        Element www = sig.sbeta.duplicate().negate();
        Element xxx = uuu.duplicate().add(www);

        Element r3_e2 = g.ehw.duplicate().powZn(xxx);
        Element uuu1 = sig.sdelta1.duplicate().negate();
        Element www1 = sig.sdelta2.duplicate().negate();
        Element xxx1 = uuu1.duplicate().add(www1);

        Element r3_e3 = g.ehg2.duplicate().powZn(xxx1);

        //eh3g2:=g.pairing.NewGT().Pair(h3,g.g2)
        //r3_e4:=g.pairing.NewGT().PowZn(eh3g2,sig.sx)

        Element r3_tep = (r3_e1.duplicate().mul(r3_e2)).duplicate().mul(r3_e3);
        Element yyy = g.pairing.pairing(sig.t3, g.w).getImmutable();
        Element ggg = g.pairing.pairing(g.g1, g.g2).getImmutable();
        Element hhh = ggg.duplicate().invert();
        Element r3 = r3_tep.duplicate().mul((yyy.duplicate().mul(hhh)).duplicate().powZn(sig.c));
        //*******************************************
        Element tt_temp2 = sig.t1.duplicate().powZn(sig.sa);
        Element tt_temp = sig.sdelta1.duplicate().negate();
        Element tt = g.u.duplicate().powZn(tt_temp);
        Element r4 = tt.duplicate().mul(tt_temp2);
        Element rr_temp2 = sig.t2.duplicate().powZn(sig.sa);
        Element rr_temp = sig.sdelta2.duplicate().negate();
        Element rr = g.v.duplicate().powZn(rr_temp);
        Element r5 = rr.duplicate().mul(rr_temp2);

        String s = "";
        s += sig.t1.toString();
        s += sig.t2.toString();
        s += sig.t3.toString();
        s += r1.toString();
        s += r2.toString();
        s += r3.toString();
        s += r4.toString();
        s += r5.toString();
        s += sig.m;
        SHA sha256 = new SHA();
        Element c_ = g.pairing.getZr().newElementFromBytes(sha256.SHA256_JAVA(s)).getImmutable();
        System.out.println("s:"+sig.m);
        //System.out.println("c-->"+sig.c);
        //System.out.println("c_-->"+c_);
        if (c_.equals(sig.c)) {
            System.out.println("verify_sign   true");
            return true;
        } else {
            System.out.println("verify_sign   false");
            return false;
        }
    }

    /*
    * @parms Sig,gmsk
    * @return Element,可理解为群成员 A
    * */
    public Element Open(PrivateKey priv, Sig sig) {
        Element temp1 = sig.t1.duplicate().powZn(priv.xi1);
        Element temp2 = sig.t2.duplicate().powZn(priv.xi2);
        Element temp3 = sig.t3.duplicate().mul((temp1.duplicate().mul(temp2)).duplicate().invert());
        return temp3;
    }

}
