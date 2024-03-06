package kr.jclab.winexetag;

import net.jsign.Signable;
import net.jsign.pe.PEFile;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.SignatureException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;

class WinExeTagUtilsTest {
    BouncyCastleProvider bouncyCastleProvider = new BouncyCastleProvider();
    SecureRandom secureRandom = new SecureRandom();

    @Test
    void getTag() throws IOException {
        PEFile peFile = new PEFile(new File("../testdata/ChromeSetup-tagged.exe"));
        CMSSignedData signedData = peFile.getSignatures().stream().findFirst().get();
        byte[] tag = WinExeTagUtils.getTag(signedData);
        assertThat(new String(tag)).isEqualTo("hello world 0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789");
    }

    @Test
    void replaceTagData() throws IOException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, OperatorCreationException, CMSException {
        byte[] newData = "GOOD DATA".getBytes();
        File tempFile = Files.createTempFile("tmp", ".exe").toFile();
        tempFile.deleteOnExit();

        FileUtils.copyFile(new File("../testdata/ChromeSetup-tagged.exe"), tempFile);
        try (PEFile peFile = new PEFile(tempFile)) {
            CMSSignedData signedData = peFile.getSignatures().stream().findFirst().get();
            CMSSignedData newSignedData = WinExeTagUtils.replaceTagData(
                    bouncyCastleProvider,
                    secureRandom,
                    signedData,
                    newData
            );
            JSignHelper.replaceSignature(peFile, newSignedData);
            peFile.save();
        }

        try (PEFile peFile = new PEFile(tempFile)) {
            CMSSignedData rereadSignedData = peFile.getSignatures().stream().findFirst().get();
            byte[] tag = WinExeTagUtils.getTag(rereadSignedData);
            assertThat(new String(tag)).isEqualTo(new String(newData));
        }
    }

    @Test
    void setTagData() throws IOException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, OperatorCreationException, CMSException, SignatureException {
        byte[] newData = "GOOD DATA".getBytes();

        File tempFile = Files.createTempFile("tmp", ".exe").toFile();
        tempFile.deleteOnExit();

        FileUtils.copyFile(new File("../testdata/ChromeSetup.exe"), tempFile);

        try (PEFile peFile = new PEFile(tempFile)) {
            CMSSignedData signedData = peFile.getSignatures().stream().findFirst().get();
            CMSSignedData newSignedData = WinExeTagUtils.replaceTagData(
                    bouncyCastleProvider,
                    secureRandom,
                    signedData,
                    newData
            );
            System.out.println("1 : " + Hex.encodeHexString(signedData.getEncoded()));
            System.out.println("2 : " + Hex.encodeHexString(newSignedData.getEncoded()));
            JSignHelper.replaceSignature(peFile, newSignedData);
            peFile.save();
        }

        try (PEFile peFile = new PEFile(tempFile)) {
            CMSSignedData rereadSignedData = peFile.getSignatures().stream().findFirst().get();
            byte[] tag = WinExeTagUtils.getTag(rereadSignedData);
            assertThat(new String(tag)).isEqualTo(new String(newData));
        }
    }
}