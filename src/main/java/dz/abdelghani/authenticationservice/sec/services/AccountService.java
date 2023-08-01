package dz.abdelghani.authenticationservice.sec.services;

import dz.abdelghani.authenticationservice.sec.entities.AppRole;
import dz.abdelghani.authenticationservice.sec.entities.AppUser;

import java.util.Collection;
import java.util.List;

public interface AccountService {
    AppUser createNewUser(AppUser appUser);
    AppRole createNewRole(AppRole appRole);
    void addRoleToUser(String username,String roleName);

    AppUser loadUserByUsername(String username);
    List<AppUser> allUsers();
}
