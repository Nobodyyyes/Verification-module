package com.example.sing.verify.mappers;

import com.example.sing.verify.domain.entities.SignatureRecord;
import com.example.sing.verify.domain.models.SignatureRecordModel;
import org.springframework.stereotype.Component;

@Component
public class SignatureRecordMapper implements BaseMapper<SignatureRecordModel, SignatureRecord> {

    @Override
    public SignatureRecordModel toModel(SignatureRecord entity) {

        if (entity == null) return null;

        return new SignatureRecordModel()
                .setId(entity.getId())
                .setFileName(entity.getFileName())
                .setSignerCommonName(entity.getSignerCommonName())
                .setSigingdate(entity.getSigingdate())
                .setDocument(entity.getDocument())
                .setSignature(entity.getSignature())
                .setCertificate(entity.getCertificate())
                .setIsValid(entity.getIsValid());
    }

    @Override
    public SignatureRecord toEntity(SignatureRecordModel model) {

        if (model == null) return null;

        return new SignatureRecord()
                .setId(model.getId())
                .setFileName(model.getFileName())
                .setSignerCommonName(model.getSignerCommonName())
                .setSigingdate(model.getSigingdate())
                .setDocument(model.getDocument())
                .setSignature(model.getSignature())
                .setCertificate(model.getCertificate())
                .setIsValid(model.getIsValid());
    }
}
