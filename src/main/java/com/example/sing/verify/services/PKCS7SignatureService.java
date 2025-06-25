package com.example.sing.verify.services;

import com.example.sing.verify.domain.models.SignatureRequest;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.operator.OperatorCreationException;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

public interface PKCS7SignatureService {

    byte[] generatePKCS7Signature(SignatureRequest request) throws NoSuchAlgorithmException, CMSException, IOException, OperatorCreationException, CertificateException;
}
