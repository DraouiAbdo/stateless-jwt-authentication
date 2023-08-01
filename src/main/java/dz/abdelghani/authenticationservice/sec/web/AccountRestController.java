package dz.abdelghani.authenticationservice.sec.web;

import dz.abdelghani.authenticationservice.sec.entities.AppRole;
import dz.abdelghani.authenticationservice.sec.entities.AppUser;
import dz.abdelghani.authenticationservice.sec.services.AccountServiceImpl;
import lombok.Data;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
public class AccountRestController {
    AccountServiceImpl accountService;

    public AccountRestController(AccountServiceImpl accountService) {
        this.accountService = accountService;
    }

    @GetMapping("/users")
    public List<AppUser> allUsers(){
        return accountService.allUsers();
    }

    @PostMapping("/users")
    public AppUser createUser(@RequestBody AppUser appUser){
        return accountService.createNewUser(appUser);
    }

    @PostMapping("/roles")
    public AppRole createRole(@RequestBody AppRole appRole){
        return accountService.createNewRole(appRole);
    }

    @PostMapping("/addRoleToUser")
    public void addRoleToUser(@RequestBody  RoleUserForm roleUserForm){
        accountService.addRoleToUser(roleUserForm.getUsername(),
                                        roleUserForm.getRoleName());
    }
}
@Data
class RoleUserForm{
    private String username;
    private String roleName;
}
