package com.example.sing.verify.services;

import java.util.List;
import java.util.Optional;

public interface BaseService<M, ID> {

    List<M> getAll();

    Optional<M> getById(ID id);

    M save(M model);

    M update(ID id, M model);

    void deleteById(ID id);
}
