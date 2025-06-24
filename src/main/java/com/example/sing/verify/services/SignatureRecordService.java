package com.example.sing.verify.services;

import com.example.sing.verify.domain.models.SignatureRecordModel;
import com.example.sing.verify.domain.models.VerifyResponse;
import org.bouncycastle.cms.CMSException;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public interface SignatureRecordService extends BaseService<SignatureRecordModel, Long> {

    VerifyResponse verify(byte[] file, byte[] signature);

    VerifyResponse verifyAndStore(String fileName, byte[] file, byte[] signature) throws CertificateException, CMSException, IOException;

    SignatureRecordModel saveRecord(String fileName, byte[] document, byte[] signature, X509Certificate certificate) throws CertificateEncodingException;

    X509Certificate extractCertificate(byte[] signature) throws CMSException, IOException, CertificateException;

    byte[] getDocumentContent(Long id);

    byte[] getSignatureContent(Long id);

    byte[] getCertificateContent(Long id);
}
