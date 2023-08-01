package dz.abdelghani.authenticationservice.sec.repositories;

import dz.abdelghani.authenticationservice.sec.entities.AppRole;
import dz.abdelghani.authenticationservice.sec.entities.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AppRoleRepository extends JpaRepository<AppRole,Long> {
    AppRole findByRoleName(String roleName);
}
