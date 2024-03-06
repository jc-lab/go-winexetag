package kr.jclab.winexetag;

import net.jsign.asn1.authenticode.AuthenticodeSignedData;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cms.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.CollectionStore;

import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.util.*;

public class WinExeTagUtils {
    public static String TAG_OID_STRING = "1.3.6.1.4.1.88888.1.32.9999";
    public static ASN1ObjectIdentifier TAG_OID = new ASN1ObjectIdentifier("1.3.6.1.4.1.88888.1.32.9999");

    public static X509CertificateHolder generateTagCertificate(
            BouncyCastleProvider bcProvider,
            SecureRandom secureRandom,
            byte[] tag
    ) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, OperatorCreationException, IOException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", bcProvider);
        kpg.initialize(new ECNamedCurveGenParameterSpec(ECNamedCurveTable.getName(SECObjectIdentifiers.secp256r1)));
        KeyPair keyPair = kpg.generateKeyPair();

        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithECDSA")
                .setProvider(bcProvider)
                .setSecureRandom(secureRandom)
                .build(keyPair.getPrivate());

        return new X509v3CertificateBuilder(
                new X500Name("CN=Unknown Issuer"),
                BigInteger.ONE,
                new Date(1546336800),
                new Date(1554112800),
                new X500Name("CN=Installation Tag Certificate"),
                SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded())
        )
                .addExtension(Extension.basicConstraints, true, new BasicConstraints(false))
                .addExtension(Extension.keyUsage, false, new KeyUsage(KeyUsage.keyCertSign))
                .addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.anyExtendedKeyUsage))
                .addExtension(new Extension(
                        new ASN1ObjectIdentifier(WinExeTagUtils.TAG_OID_STRING),
                        false,
                        new DEROctetString(tag)
                ))
                .build(signer);
    }

    public static CMSSignedData replaceTagCertificate(CMSSignedData originalSignature, X509CertificateHolder tagCertificate) throws CMSException, IOException {
        ArrayList<X509CertificateHolder> certificates = new ArrayList<>();
        for (Object o : (CollectionStore) originalSignature.getCertificates()) {
            certificates.add((X509CertificateHolder) o);
        }

        int existingIndex = -1;
        for (int i=0; i < certificates.size(); i++) {
            if (TagCertificateSelector.INSTANCE.match(certificates.get(i))) {
                existingIndex = i;
                break;
            }
        }
        if (existingIndex != -1) {
            certificates.remove(existingIndex);
        }

        certificates.add(tagCertificate);

        ContentInfo contentInfo = originalSignature.toASN1Structure();
        SignedData signedData = SignedData.getInstance(contentInfo.getContent());
        ASN1Encodable newSignedData = serializeAuthenticodeSignedData(
                signedData.getDigestAlgorithms(),
                signedData.getEncapContentInfo(),
                createCertSet(certificates),
                signedData.getCRLs(),
                signedData.getSignerInfos()
        );
        ContentInfo newContentInfo = new ContentInfo(CMSObjectIdentifiers.signedData, newSignedData);
        return new CMSSignedData(
                new CMSProcessableByteArray(newContentInfo.getContentType(), newSignedData.toASN1Primitive().getEncoded("DER")),
                newContentInfo
        );
    }

    public static CMSSignedData replaceTagData(
            BouncyCastleProvider bcProvider,
            SecureRandom secureRandom,
            CMSSignedData signedData,
            byte[] tag
    ) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException, OperatorCreationException, CMSException {
        return replaceTagCertificate(signedData, generateTagCertificate(bcProvider, secureRandom, tag));
    }

    public static byte[] getTag(CMSSignedData signedData) {
        return signedData.getCertificates().getMatches(TagCertificateSelector.INSTANCE)
                .stream()
                .findFirst()
                .flatMap(it -> Optional.ofNullable(it.getExtension(TAG_OID)))
                .map(it -> it.getExtnValue().getOctets())
                .orElse(null);
    }

    static ASN1Primitive serializeAuthenticodeSignedData(
            ASN1Set     digestAlgorithms,
            ContentInfo contentInfo,
            ASN1Set     certificates,
            ASN1Set     crls,
            ASN1Set     signerInfos
    ) {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new ASN1Integer(1));
        v.add(digestAlgorithms);
        v.add(contentInfo);

        if (certificates != null) {
            v.add(new DERTaggedObject(false, 0, certificates));
        }

        v.add(signerInfos);

        return new BERSequence(v);
    }

    static ASN1Set createCertSet(List<? extends X509CertificateHolder> certs)
    {
        ArrayList<ASN1Encodable> list = new ArrayList<>();
        for (X509CertificateHolder holder : certs) {
            list.add(holder.toASN1Structure());
        }
        return createBerSetFromList(list);
    }

    static ASN1Set createBerSetFromList(List derObjects)
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        for (Iterator it = derObjects.iterator(); it.hasNext(); )
        {
            v.add((ASN1Encodable)it.next());
        }

        return new BERSet(v);
    }
}
