package dz.abdelghani.authenticationservice.sec.repositories;

import dz.abdelghani.authenticationservice.sec.entities.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AppUserRepository extends JpaRepository<AppUser,Long> {
    AppUser findByUsername(String username);
}
