package com.example.sing.verify.services.impl;

import com.example.sing.verify.domain.entities.SignatureRecord;
import com.example.sing.verify.domain.models.SignatureRecordModel;
import com.example.sing.verify.domain.models.VerifyResponse;
import com.example.sing.verify.mappers.BaseMapper;
import com.example.sing.verify.repositories.SignatureRecordRepository;
import com.example.sing.verify.services.SignatureRecordService;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.util.Store;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;

@Service
public class SignatureRecordServiceImpl extends BaseServiceImpl<SignatureRecordModel, SignatureRecord, Long> implements SignatureRecordService {

    private final SignatureRecordRepository signatureRecordRepository;

    public SignatureRecordServiceImpl(SignatureRecordRepository signatureRecordRepository, BaseMapper<SignatureRecordModel, SignatureRecord> baseMapper) {
        super(signatureRecordRepository, baseMapper);
        this.signatureRecordRepository = signatureRecordRepository;
    }

    @Override
    public VerifyResponse verify(byte[] file, byte[] signature) {

        try {
            CMSSignedData cms = new CMSSignedData(new CMSProcessableByteArray(file), signature);

            SignerInformationStore signers = cms.getSignerInfos();

            SignerInformation signer = signers.getSigners().iterator().next();

            Store<X509CertificateHolder> certificateStore = cms.getCertificates();

            X509CertificateHolder certificateHolder = (X509CertificateHolder) certificateStore.getMatches(signer.getSID()).iterator().next();

            JcaSimpleSignerInfoVerifierBuilder builder = new JcaSimpleSignerInfoVerifierBuilder();

            boolean verified = signer.verify(builder.build(certificateHolder));

            String signerName = certificateHolder.getSubject().toString();

            return new VerifyResponse(verified, signerName, verified ? "OK" : "Signature invalid");
        } catch (Exception e) {
            return new VerifyResponse(false, null, "Error: %s".formatted(e.getMessage()));
        }
    }

    @Override
    public VerifyResponse verifyAndStore(String fileName, byte[] file, byte[] signature) throws CertificateException, CMSException, IOException {

        VerifyResponse response = verify(file, signature);

        if (response.getIsValid()) {

            X509Certificate certificate = extractCertificate(signature);

            saveRecord(fileName, file, signature, certificate);
        }

        return response;
    }

    @Override
    public SignatureRecordModel saveRecord(String fileName, byte[] document, byte[] signature, X509Certificate certificate) throws CertificateEncodingException {

        SignatureRecordModel model = new SignatureRecordModel()
                .setFileName(fileName)
                .setDocument(document)
                .setSignature(signature)
                .setCertificate(certificate.getEncoded())
                .setSignerCommonName(certificate.getSubjectX500Principal().getName())
                .setSigingdate(new Date())
                .setIsValid(true);

        return save(model);
    }

    @Override
    public X509Certificate extractCertificate(byte[] signature) throws CMSException, IOException, CertificateException {

        try {
            CMSSignedData cms = new CMSSignedData(signature);

            Store<X509CertificateHolder> certificates = cms.getCertificates();

            X509CertificateHolder certificateHolder = certificates.getMatches(null).iterator().next();

            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(certificateHolder.getEncoded()));
        } catch (Exception e) {
            throw new RuntimeException("Failed to extract certificate", e);
        }
    }

    @Override
    public byte[] getDocumentContent(Long id) {
        return signatureRecordRepository.findById(id).orElseThrow().getDocument();
    }

    @Override
    public byte[] getSignatureContent(Long id) {
        return signatureRecordRepository.findById(id).orElseThrow().getSignature();
    }

    @Override
    public byte[] getCertificateContent(Long id) {
        return signatureRecordRepository.findById(id).orElseThrow().getCertificate();
    }
}
