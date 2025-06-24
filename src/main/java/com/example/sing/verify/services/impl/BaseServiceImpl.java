package com.example.sing.verify.services.impl;

import com.example.sing.verify.mappers.BaseMapper;
import com.example.sing.verify.services.BaseService;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public class BaseServiceImpl<M, E, ID> implements BaseService<M, ID> {

    protected final JpaRepository<E, ID> repository;

    protected final BaseMapper<M, E> baseMapper;

    public BaseServiceImpl(JpaRepository<E, ID> repository, BaseMapper<M, E> baseMapper) {
        this.repository = repository;
        this.baseMapper = baseMapper;
    }

    /**
     * Retrieves all entities from the repository and maps them to their corresponding models.
     *
     * @return a list of models representing all entities in the repository
     */
    @Override
    public List<M> getAll() {
        return baseMapper.toModels(repository.findAll());
    }

    /**
     * Retrieves an entity by its ID and maps it to its corresponding model.
     *
     * @param id the ID of the entity to retrieve
     * @return an Optional containing the model if found, or an empty Optional if not found
     */
    @Override
    public Optional<M> getById(ID id) {
        return repository.findById(id).map(baseMapper::toModel);
    }

    /**
     * Saves a model by converting it to an entity, persisting it in the repository,
     * and then mapping the saved entity back to a model.
     *
     * @param model the model to save
     * @return the saved model
     */
    @Override
    public M save(M model) {
        return baseMapper.toModel(repository.save(baseMapper.toEntity(model)));
    }

    /**
     * Updates an existing entity by its ID with the provided model.
     * Ensures the ID is not null and the entity exists in the repository.
     *
     * @param id    the ID of the entity to update
     * @param model the model containing updated data
     * @return the updated model
     * @throws IllegalArgumentException if the ID is null
     * @throws IllegalStateException    if the entity with the given ID does not exist
     */
    @Override
    public M update(ID id, M model) {

        if (id == null) {
            throw new IllegalArgumentException("ID must be null");
        }

        if (!repository.existsById(id)) {
            throw new IllegalStateException("Entity with ID %s not found".formatted(id));
        }

        return save(model);
    }

    /**
     * Deletes an entity by its ID.
     *
     * @param id the ID of the entity to delete
     * @throws IllegalArgumentException if the ID is null
     */
    @Override
    public void deleteById(ID id) {
        repository.deleteById(id);
    }
}