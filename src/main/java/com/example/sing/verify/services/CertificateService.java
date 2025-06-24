package com.example.sing.verify.services;

import com.example.sing.verify.domain.models.CertificateInfo;
import org.bouncycastle.cms.CMSException;

import java.security.cert.CertificateException;

public interface CertificateService {

    CertificateInfo extractCertificateInfo(byte[] signature) throws CMSException, CertificateException;
}
