package com.example.sing.verify.repositories;

import com.example.sing.verify.domain.entities.SignatureRecord;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SignatureRecordRepository extends JpaRepository<SignatureRecord, Long> {
}
