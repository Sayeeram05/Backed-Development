package com.sriram.project.emergency_notifier.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.sriram.project.emergency_notifier.entity.Contact;
import com.sriram.project.emergency_notifier.entity.User;

@Repository
public interface ContactRepository extends JpaRepository<Contact, Long> {
    
    List<Contact> findByUser(User user);
    
    List<Contact> findByUserId(Long userId);
    
    void deleteByUserId(Long userId);
}