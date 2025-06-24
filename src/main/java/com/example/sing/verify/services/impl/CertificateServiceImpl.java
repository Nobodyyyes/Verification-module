package com.example.sing.verify.services.impl;

import com.example.sing.verify.domain.models.CertificateInfo;
import com.example.sing.verify.services.CertificateService;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Store;
import org.springframework.stereotype.Service;

import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class CertificateServiceImpl implements CertificateService {

    @Override
    public CertificateInfo extractCertificateInfo(byte[] signature) throws CMSException, CertificateException {

        CMSSignedData cmsSignedData = new CMSSignedData(signature);

        SignerInformationStore signerInfos = cmsSignedData.getSignerInfos();

        SignerInformation signerInfo = signerInfos.getSigners().iterator().next();

        Store<X509CertificateHolder> certificateHolder = cmsSignedData.getCertificates();

        Collection<X509CertificateHolder> certificateHolderCollection = certificateHolder.getMatches(signerInfo.getSID());

        if (certificateHolderCollection.isEmpty()) {
            throw new IllegalArgumentException("Certificate not found in signature");
        }

        X509CertificateHolder certHolder = certificateHolderCollection.iterator().next();

        X509Certificate certificate = new JcaX509CertificateConverter()
                .setProvider(new BouncyCastleProvider())
                .getCertificate(certHolder);

        return new CertificateInfo()
                .setSubject(certificate.getSubjectX500Principal().getName())
                .setIssuer(certificate.getIssuerX500Principal().getName())
                .setValidFrom(certificate.getNotBefore())
                .setValidTo(certificate.getNotAfter())
                .setSerialNumber(certificate.getSerialNumber().toString())
                .setSignatureAlgorithm(certificate.getSigAlgName())
                .setPublicKeyAlgorithm(certificate.getPublicKey().getAlgorithm())
                .setKeyUsage(getKeyUsage(certificate))
                .setExtendedKeyUsage(getExtendedKeyUsage(certificate))
                .setSubjectAlternativeNames(getSubjectAltNames(certificate));
    }

    private List<String> getKeyUsage(X509Certificate cert) {
        String[] usageNames = {
                "digitalSignature", "nonRepudiation", "keyEncipherment",
                "dataEncipherment", "keyAgreement", "keyCertSign",
                "cRLSign", "encipherOnly", "decipherOnly"
        };

        boolean[] usages = cert.getKeyUsage();
        if (usages == null) return Collections.emptyList();

        List<String> result = new ArrayList<>();
        for (int i = 0; i < usages.length && i < usageNames.length; i++) {
            if (usages[i]) result.add(usageNames[i]);
        }
        return result;
    }

    private List<String> getExtendedKeyUsage(X509Certificate cert) {
        try {
            List<String> oids = cert.getExtendedKeyUsage();
            if (oids == null) return Collections.emptyList();

            return oids.stream().map(oid -> switch (oid) {
                case "1.3.6.1.5.5.7.3.1" -> "TLS Web Server Authentication";
                case "1.3.6.1.5.5.7.3.2" -> "TLS Web Client Authentication";
                case "1.3.6.1.5.5.7.3.3" -> "Code Signing";
                case "1.3.6.1.5.5.7.3.4" -> "Email Protection";
                default -> "OID: " + oid;
            }).collect(Collectors.toList());

        } catch (CertificateParsingException e) {
            return Collections.emptyList();
        }
    }

    private List<String> getSubjectAltNames(X509Certificate cert) {
        try {
            Collection<List<?>> san = cert.getSubjectAlternativeNames();
            if (san == null) return Collections.emptyList();

            return san.stream()
                    .map(entry -> entry.get(1).toString())
                    .collect(Collectors.toList());
        } catch (CertificateParsingException e) {
            return Collections.emptyList();
        }
    }
}
