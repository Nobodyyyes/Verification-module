package com.example.sing.verify.services.impl;

import com.example.sing.verify.domain.models.SignatureRequest;
import com.example.sing.verify.services.PKCS7SignatureService;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.List;

@Service
public class PKCS7SignatureServiceImpl implements PKCS7SignatureService {

    /**
     * Added provider BouncyCastle
     */
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Override
    public byte[] generatePKCS7Signature(SignatureRequest request)
            throws NoSuchAlgorithmException, CMSException, IOException,
            OperatorCreationException, CertificateException {

        // 1. Генерация ключей
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(request.getKeySize());
        KeyPair keyPair = keyGen.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();

        // 2. Сбор информации о владельце (Subject / Issuer)
        String dn = String.format("CN=%s, O=%s, C=%s",
                request.getSubjectCN(),
                request.getOrganization(),
                request.getCountry());

        X500Name issuer = new X500Name(dn);
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        Date notBefore = java.sql.Date.valueOf(request.getValidFrom());
        Date notAfter = java.sql.Date.valueOf(request.getValidTo());

        // 3. Создание X.509 сертификата
        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer, serial, notBefore, notAfter, issuer, keyPair.getPublic()
        );

        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSA").build(privateKey);
        X509CertificateHolder certHolder = certBuilder.build(contentSigner);
        X509Certificate certificate = new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(certHolder);

        // 4. Создание CMS/PKCS7 подписи
        CMSTypedData cmsData = new CMSProcessableByteArray(request.getData());
        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();

        SignerInfoGenerator signerInfoGenerator = new JcaSignerInfoGeneratorBuilder(
                new JcaDigestCalculatorProviderBuilder().build()
        ).build(contentSigner, certificate);

        generator.addSignerInfoGenerator(signerInfoGenerator);

        List<X509Certificate> certList = Collections.singletonList(certificate);
        Store<X509CertificateHolder> certs = new JcaCertStore(certList);

        generator.addCertificates(certs);

        CMSSignedData signedData = generator.generate(cmsData, true);
        return signedData.getEncoded();
    }

}
